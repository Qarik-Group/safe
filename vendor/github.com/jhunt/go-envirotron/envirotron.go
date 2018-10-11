package envirotron

import (
	"strings"
	"strconv"
	"reflect"
	"os"
)

func override(t reflect.Type, v *reflect.Value) {
	if t.Kind() != reflect.Struct {
		return
	}
	if !v.CanSet() {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue
		}
		if _, set := field.Tag.Lookup("env"); !set {
			switch field.Type.Kind() {
			case reflect.Struct, reflect.Ptr:
				valu := v.Field(i)
				override(t.Field(i).Type, &valu)
			}
			continue
		}
		tag := field.Tag.Get("env")
		if e := os.Getenv(tag); e != "" {
			switch field.Type.Kind() {
			case reflect.String:
				v.Field(i).Set(reflect.ValueOf(stringify(e)))

			case reflect.Bool:
				v.Field(i).Set(reflect.ValueOf(boolify(e)))

			case reflect.Int:
				v.Field(i).Set(reflect.ValueOf(intify(e, 0)))

			case reflect.Int8:
				v.Field(i).Set(reflect.ValueOf(intify(e, 8)))

			case reflect.Int16:
				v.Field(i).Set(reflect.ValueOf(intify(e, 16)))

			case reflect.Int32:
				v.Field(i).Set(reflect.ValueOf(intify(e, 32)))

			case reflect.Int64:
				v.Field(i).Set(reflect.ValueOf(intify(e, 64)))

			case reflect.Uint:
				v.Field(i).Set(reflect.ValueOf(uintify(e, 0)))

			case reflect.Uint8:
				v.Field(i).Set(reflect.ValueOf(uintify(e, 8)))

			case reflect.Uint16:
				v.Field(i).Set(reflect.ValueOf(uintify(e, 16)))

			case reflect.Uint32:
				v.Field(i).Set(reflect.ValueOf(uintify(e, 32)))

			case reflect.Uint64:
				v.Field(i).Set(reflect.ValueOf(uintify(e, 64)))

			case reflect.Float32:
				v.Field(i).Set(reflect.ValueOf(floatify(e, 32)))

			case reflect.Float64:
				v.Field(i).Set(reflect.ValueOf(floatify(e, 64)))
			}
		}
	}
}

func Override(thing interface{}) {
	t := reflect.TypeOf(thing)
	v := reflect.ValueOf(thing)
	for t.Kind() == reflect.Ptr {
		v = v.Elem()
		t = v.Type()
	}

	override(t, &v)
}

func stringify(s string) string {
	return s
}

func boolify(s string) bool {
	switch strings.ToLower(s) {
	case "y", "yes", "1", "true": return true
	}
	return false
}

func intify(s string, w int) interface{} {
	i64, err := strconv.ParseInt(s, 10, w)
	if err != nil {
		i64 = 0
	}

	switch w {
	case 0:
		return int(i64)
	case 8:
		return int8(i64)
	case 16:
		return int16(i64)
	case 32:
		return int32(i64)
	case 64:
		return int64(i64)
	}
	return int(0)
}

func uintify(s string, w int) interface{} {
	u64, err := strconv.ParseUint(s, 10, w)
	if err != nil {
		u64 = 0
	}

	switch w {
	case 0:
		return uint(u64)
	case 8:
		return uint8(u64)
	case 16:
		return uint16(u64)
	case 32:
		return uint32(u64)
	case 64:
		return uint64(u64)
	}
	return uint(0)
}

func floatify(s string, w int) interface{} {
	f64, err := strconv.ParseFloat(s, w)
	if err != nil {
		f64 = 0.0
	}

	switch w {
	case 32:
		return float32(f64)
	case 64:
		return float64(f64)
	}
	return float32(0)
}
