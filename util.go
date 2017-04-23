// Author:   Toke Høiland-Jørgensen (toke@toke.dk)
// Date:     13 Apr 2017
// Copyright (c) 2017, Toke Høiland-Jørgensen
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"net"
	"reflect"
)

// borrowed from github.com/spf13/viper/util.go
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Checks for unset exported fields in a struct. Only checks simple (comparable)
// field types that are not of type bool
func checkFields(i interface{}) error {
	val := reflect.Indirect(reflect.ValueOf(i))
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		f := typ.Field(i)
		v := val.Field(i)
		t := v.Type()
		if len(f.PkgPath) > 0 {
			// Unexported struct field
			continue
		}
		// A bool set to false would be considered unset
		if t.Kind() == reflect.Bool {
			continue
		}
		if t.Comparable() && reflect.Zero(t).Interface() == v.Interface() {
			n := f.Tag.Get("mapstructure")
			if len(n) == 0 {
				n = f.Name
			}
			return fmt.Errorf("Required key '%s' is unset.", n)
		}
	}

	return nil
}

func inNets(ip net.IP, nets []*net.IPNet) bool {

	for _, net := range nets {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}
