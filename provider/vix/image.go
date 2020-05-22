package vix

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"log"
	"context"
	"net/url"
	"strings"
	"os"
	"path"
	"path/filepath"

//	"github.com/dustin/go-humanize"
	getter "github.com/hashicorp/go-getter"
)

// A virtual machine image definition
type Image struct {
	// Image URL where to download from
	URL string
	// Checksum of the image, used to check integrity after downloading it
	Checksum string
	// Algorithm use to check the checksum
	ChecksumType string
	// Password to decrypt the virtual machine if it is encrypted. This is used by
	// VIX to be able to open the virtual machine
	Password string
	// Internal file reference
	file *os.File
}

// Simple utility function for determining the hash type to use
func determineHashType(checksum string) (string, error) {

	// Create a lookup table based on the checksum length
	lookup := map[int]string{
		2 * md5.Size:  "md5",
		2 * sha1.Size: "sha1",
		2 * sha256.Size: "sha256",
		2 * sha512.Size: "sha512",
	}

	// Search through our supported hashes for one that matches our length
	if res, ok := lookup[len(checksum)]; ok {
		return res, nil

	// Otherwise return an error to the user so they know what's up.
	} else {
		return "", fmt.Errorf("Unable to determine hash type for checksum %s", checksum)
	}
}

// Downloads and a virtual machine image
func (img *Image) Download(basePath string) error {
	var download_and_verify func(int, int) error

	// Figure out the name from the URL since go-getter is dumb and requires
	// us to parse everything out ourselves. (Ideally we'd be given a handle)
	u, err := url.Parse(img.URL)
	if err != nil {
		return err
	}

	_, filename := path.Split(u.Path)
	if filename == "" {
		filename = "unnamed"
	}

	// Check if we were given a checksum and a type.
	has_checksum := false
	if img.Checksum != "" {

		// Check the hash type of the checksum we were given.
		if res, err := determineHashType(img.Checksum); err != nil {
			return err

		// If we weren't given the checksum type, then we can now assign it
		// from what we determined.
		} else if img.ChecksumType == "" {
			img.ChecksumType = res

		// If it doesn't match, then we should just fail here and let the
		// user know that they need to fix their shit.
		} else if strings.ToLower(img.ChecksumType) != res {
			return fmt.Errorf("Expected a checksum type of %s for checksum but received %s instead", res, strings.ToLower(img.ChecksumType))
		}

		// Now we know for sure that we got a checksum and a matching type.
		has_checksum = true

	// If there was no checksum, then warn the user that we're going to
	// download the file every-single-time and that they should really do
	// something about it
	} else {
		log.Printf("[WARNING] No checksum was provided. This will result in an individual download for each vm.")
	}

	// Should be good to go, so let's make a temp directory and ensure it exists
	// so that we can download a file to it.
	tmpPath := os.TempDir()
	os.MkdirAll(tmpPath, 0740)
	filePath := filepath.Join(tmpPath, filename)

	// Construct the client that we'll use to fetch things with
	client := &getter.Client{
		Ctx: context.Background(),
		Pwd: basePath,
		Mode: getter.ClientModeFile,

		// Our URL and where to put it
		Src: img.URL,
		Dst: filePath,
	}

	// Define some closures that we can recurse with when the checksum fails
	download := func() error {

		// Fetch the url that we were given, and error out if that didn't work.
		if err := client.Get(); err != nil {
			return fmt.Errorf("Unable to fetch requested URL: %s", err)

		// It worked. So we can return here.
		} else {
			return nil
		}
	}

	// Now we'll open up the file so that we can check things out. This tries
	// to preserve the author's previous logic..somewhat.
	verify := func() error {
		log.Printf("[DEBUG] Opening %s...", filePath)
		img.file, err = os.Open(filePath)
		if err != nil {
			log.Printf("[DEBUG] %s file does not exist", filename)
			return err
		}

		if err = img.verify(); err != nil {
			log.Printf("[DEBUG] File on disk does not match current checksum")
			img.file.Close()
			return err
		}

		// If we were successful, then move it to the correct place
		imagePath := filepath.Join(basePath, "images", img.Checksum)
		os.MkdirAll(imagePath, 0740)
		outputPath := filepath.Join(imagePath, filename)
		if err = os.Rename(filePath, outputPath); err != nil {
			return fmt.Errorf("Unable to move file to correct place: %s", err)
		}
		log.Printf("[DEBUG] Stored file under images at %s", outputPath)
		return nil
	}

	// Recursive function to repeatedly download and verify some number of times
	download_and_verify = func(try, tries int) error {
		if try >= tries {
			return fmt.Errorf("Failed downloading file. Giving up!")
		}

		// Perform actual download. Error out if we're unable to accomplish this.
		if err = download(); err != nil {
			return err
		}

		// Unfortunately there's a race here between downloading the file and
		// opening it. I tried to tell hashicorp developers about this miserable
		// design, but nobody listens to aging infosec people...

		// Verify that the file is what the user expects. If it is, then we can
		// simply return here.
		if err = verify(); err == nil {
			return nil
		}

		// Otherwise, the checksum doesn't match. So remove it and tail-recurse.
		log.Printf("[DEBUG] Downloading file again (try %d)...", 1 + try)
		return download_and_verify(try + 1, tries)
	}

	// If there was no checksum provided, then we were asked to download this
	// every single time... So we will simply download it once, move it to the
	// correct place (based on its checksum, open it for its handle, and then
	// we can blindly leave.
	if !has_checksum {
		if err = download(); err != nil {
			return fmt.Errorf("Error trying to download file: %s", err)
		}

		// Open it and assign the handle to our object so that other things
		// can interact with it.
		img.file, err = os.Open(filePath)
		if err != nil {
			return err
		}

		// Calculate the checksum since we weren't given one
		if err = img.calculate(); err != nil {
			return fmt.Errorf("Error trying to determine checksum: %s", err)
		}

		// Move the file to the correct place
		imagePath := filepath.Join(basePath, "images", img.Checksum)
		os.MkdirAll(imagePath, 0740)
		outputPath := filepath.Join(imagePath, filename)
		if err = os.Rename(filePath, outputPath); err != nil {
			return fmt.Errorf("Unable to move file to correct place: %s", err)
		}
		log.Printf("[DEBUG] Stored file under images at %s", outputPath)
		return nil
	}

	// So first thing we'll do is try and open the file in case it was already
	// previously downloaded.
	log.Printf("[DEBUG] Opening %s...", filePath)
	img.file, err = os.Open(filePath)

	// If we couldn't open, then we need to download it. So we can simply enter
	// our rinse-and-repeat cycle here. (5 times)
	if err != nil {
		log.Printf("[DEBUG] %s file does not exist. Downloading it...", filename)
		return download_and_verify(0, 5)

	}

	// We were actually able to open the file. We only need to validate that it
	// matches our checksum. If so, then we're good and can leave.
	if err = img.verify(); err == nil {
		return nil

	// Otherwise, we close the handle because we're going to try to download it again.
	} else {
		img.file.Close()
		log.Printf("[ERROR] Unable to verify checksum: %s", err)
	}

	// Complain to the user and then try downloading it a few times.
	log.Printf("[DEBUG] File on disk does not match current checksum. Downloading it...")
	return download_and_verify(0, 5)
}

// Verifies the image package integrity after it is downloaded
func (img *Image) verify() error {
	// Makes sure the file cursor is positioned at the beginning of the file
	_, err := img.file.Seek(0, 0)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Verifying image checksum (%s)...", img.ChecksumType)
	var hasher hash.Hash

	switch img.ChecksumType {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		return fmt.Errorf("[ERROR] Crypto algorithm no supported: %s", img.ChecksumType)
	}

	_, err = io.Copy(hasher, img.file)
	if err != nil {
		return err
	}

	result := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Printf("[DEBUG] Calculated image checksum as %s", result)

	if result != img.Checksum {
		return fmt.Errorf("[ERROR] Checksum does not match\n Result: %s\n Expected: %s", result, img.Checksum)
	}

	return nil
}

// Calculate the image package integrity once it has been downloaded
func (img *Image) calculate() error {
	// Makes sure the file cursor is positioned at the beginning of the file
	_, err := img.file.Seek(0, 0)
	if err != nil {
		return err
	}

	var hasher hash.Hash

	switch img.ChecksumType {
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	default:
		img.ChecksumType = "sha256"
		hasher = sha256.New()
	}

	log.Printf("[DEBUG] Calculating image checksum (%s)...", img.ChecksumType)
	_, err = io.Copy(hasher, img.file)
	if err != nil {
		return err
	}

	img.Checksum = fmt.Sprintf("%x", hasher.Sum(nil))
	log.Printf("[DEBUG] Calculated image checksum as %s", img.Checksum)
	return nil
}
