package snapshot

import (
	"reflect"
)

type snapval struct {
	typ  reflect.Type
	slot *reflect.Value
	orig interface{}
}

type Snapshot struct {
	values []snapval
}

func Take(thing interface{}) (Snapshot, error) {
	ss := Snapshot{values: make([]snapval, 0)}
	v := reflect.ValueOf(thing)

	extend(&ss, v.Elem().Type(), v.Elem())
	return ss, nil
}

func (ss Snapshot) Revert() error {
	for _, v := range ss.values {
		switch v.orig.(type) {
		case nil:
			/* reflect panics if we try to revert to nil
			   this only affects interface{} members. */
		default:
			v.slot.Set(reflect.ValueOf(v.orig).Convert(v.typ))
		}
	}
	return nil
}

func extend(ss *Snapshot, t reflect.Type, v reflect.Value) {
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).PkgPath == "" {
				extend(ss, t.Field(i).Type, v.Field(i))
			}
		}

	case reflect.Slice, reflect.Array:
		ss.values = append(ss.values, snapval{typ: t, slot: &v, orig: v.Interface()})
		for i := 0; i < v.Len(); i++ {
			extend(ss, v.Index(i).Type(), v.Index(i))
		}

	default:
		ss.values = append(ss.values, snapval{typ: t, slot: &v, orig: v.Interface()})
	}
}
