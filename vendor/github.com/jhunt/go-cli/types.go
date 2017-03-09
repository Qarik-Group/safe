package cli

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type option struct {
	Kind    reflect.Kind
	Value   *reflect.Value
	Default *string
	Shorts  string
	Longs   []string
}

type context struct {
	Command string /* canonical name */
	Options []option
	Subs    map[string]context
}

func (c context) findLong(subs []string, name string) (option, error) {
	/* try the options on this level */
	for _, o := range c.Options {
		for _, l := range o.Longs {
			if l == name {
				return o, nil
			}
		}
	}

	/* if we have no more sub-commands to descend into, we're hooped */
	if len(subs) == 0 {
		return option{}, fmt.Errorf("unrecognized flag `--%s`", name)
	}

	if sub, ok := c.Subs[subs[0]]; ok {
		return sub.findLong(subs[1:], name)
	}

	/* sub-command must not exist; this is probably a bug in `cli` itself... */
	return option{}, fmt.Errorf("unrecognized sub-command `%s`", subs[0])
}

func (c context) findShort(subs []string, name string) (option, error) {
	/* try the options on this level */
	for _, o := range c.Options {
		if strings.IndexAny(o.Shorts, name) >= 0 {
			return o, nil
		}
	}

	/* if we have no more sub-commands to descend into, we're hooped */
	if len(subs) == 0 {
		return option{}, fmt.Errorf("unrecognized flag `-%s`", name)
	}

	if sub, ok := c.Subs[subs[0]]; ok {
		return sub.findShort(subs[1:], name)
	}

	/* sub-command must not exist; this is probably a bug in `cli` itself... */
	return option{}, fmt.Errorf("unrecognized sub-command `%s`", subs[0])
}

func (o option) enable(on bool) {
	o.Value.Set(reflect.ValueOf(on))
}

func (o option) set(raw string) error {
	var (
		err error
		v   interface{}
	)

	switch o.Kind {
	case reflect.String:
		v = raw
		break

	case reflect.Int:
		v, err = intify(raw, 0)
		break

	case reflect.Int8:
		v, err = intify(raw, 8)
		break

	case reflect.Int16:
		v, err = intify(raw, 16)
		break

	case reflect.Int32:
		v, err = intify(raw, 32)
		break

	case reflect.Int64:
		v, err = intify(raw, 64)
		break

	case reflect.Uint:
		v, err = uintify(raw, 0)
		break

	case reflect.Uint8:
		v, err = uintify(raw, 8)
		break

	case reflect.Uint16:
		v, err = uintify(raw, 16)
		break

	case reflect.Uint32:
		v, err = uintify(raw, 32)
		break

	case reflect.Uint64:
		v, err = uintify(raw, 64)
		break

	case reflect.Float32:
		v, err = floatify(raw, 32)
		break

	case reflect.Float64:
		v, err = floatify(raw, 64)
		break
	}

	if err != nil {
		return err
	}

	o.Value.Set(reflect.ValueOf(v))
	return nil
}

func intify(s string, w int) (interface{}, error) {
	i64, err := strconv.ParseInt(s, 10, w)
	if err != nil {
		return nil, err
	}

	switch w {
	case 0:
		return int(i64), nil
	case 8:
		return int8(i64), nil
	case 16:
		return int16(i64), nil
	case 32:
		return int32(i64), nil
	case 64:
		return int64(i64), nil
	}
	return nil, fmt.Errorf("unrecognized integer width %d", w)
}

func uintify(s string, w int) (interface{}, error) {
	u64, err := strconv.ParseUint(s, 10, w)
	if err != nil {
		return nil, err
	}

	switch w {
	case 0:
		return uint(u64), nil
	case 8:
		return uint8(u64), nil
	case 16:
		return uint16(u64), nil
	case 32:
		return uint32(u64), nil
	case 64:
		return uint64(u64), nil
	}
	return nil, fmt.Errorf("unrecognized integer width %d", w)
}

func floatify(s string, w int) (interface{}, error) {
	f64, err := strconv.ParseFloat(s, w)
	if err != nil {
		return nil, err
	}

	switch w {
	case 32:
		return float32(f64), nil
	case 64:
		return float64(f64), nil
	}
	return nil, fmt.Errorf("unrecognized floating point width %d", w)
}
