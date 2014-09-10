package terraform

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform/config"
)

func TestResource_Vars(t *testing.T) {
	r := new(Resource)

	if len(r.Vars()) > 0 {
		t.Fatalf("bad: %#v", r.Vars())
	}

	r = &Resource{
		Id: "key",
		State: &ResourceState{
			Attributes: map[string]string{
				"foo": "bar",
			},
		},
	}

	expected := map[string]string{
		"key.foo": "bar",
	}
	actual := r.Vars()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("bad: %#v", actual)
	}
}

func TestResourceConfigGet(t *testing.T) {
	cases := []struct {
		Config map[string]interface{}
		Vars   map[string]string
		Key    string
		Value  interface{}
	}{
		{
			Config: map[string]interface{}{
				"foo": "${var.foo}",
			},
			Key:   "foo",
			Value: "${var.foo}",
		},

		{
			Config: map[string]interface{}{
				"foo": "${var.foo}",
			},
			Vars:  map[string]string{"foo": "bar"},
			Key:   "foo",
			Value: "bar",
		},

		{
			Config: map[string]interface{}{
				"foo": []interface{}{1, 2, 5},
			},
			Key:   "foo.0",
			Value: 1,
		},

		{
			Config: map[string]interface{}{
				"foo": []interface{}{1, 2, 5},
			},
			Key:   "foo.5",
			Value: nil,
		},
	}

	for i, tc := range cases {
		rawC, err := config.NewRawConfig(tc.Config)
		if err != nil {
			t.Fatalf("err: %s", err)
		}
		rc := NewResourceConfig(rawC)

		if tc.Vars != nil {
			ctx := NewContext(&ContextOpts{Variables: tc.Vars})
			if err := rc.interpolate(ctx); err != nil {
				t.Fatalf("err: %s", err)
			}
		}

		v, _ := rc.Get(tc.Key)
		if !reflect.DeepEqual(v, tc.Value) {
			t.Fatalf("%d bad: %#v", i, v)
		}
	}
}
