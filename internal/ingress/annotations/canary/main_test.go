/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package canary

import (
	"testing"

	yaml "gopkg.in/yaml.v2"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"

	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

func buildIngress() *extensions.Ingress {
	defaultBackend := extensions.IngressBackend{
		ServiceName: "default-backend",
		ServicePort: intstr.FromInt(80),
	}

	return &extensions.Ingress{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
		},
		Spec: extensions.IngressSpec{
			Backend: &extensions.IngressBackend{
				ServiceName: "default-backend",
				ServicePort: intstr.FromInt(80),
			},
			Rules: []extensions.IngressRule{
				{
					Host: "foo.bar.com",
					IngressRuleValue: extensions.IngressRuleValue{
						HTTP: &extensions.HTTPIngressRuleValue{
							Paths: []extensions.HTTPIngressPath{
								{
									Path:    "/foo",
									Backend: defaultBackend,
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestAnnotations(t *testing.T) {
	ing := buildIngress()

	data := map[string]string{}
	ing.SetAnnotations(data)

	tests := []struct {
		title              string
		canaryWeight       int
		canaryHeader       string
		canaryNginxHeader  string
		canaryHeaderValues []string
		canaryCookie       string
		canaryNginxCookie  string
		canaryCookieValues []string
		expErr             bool
	}{
		{"canary with valid weight", 10, "", "", nil, "", "", nil, false},
		{"canary with negative weight", -5, "", "", nil, "", "", nil, true},
		{"canary with invalid weight", 110, "", "", nil, "", "", nil, true},
		{"canary with valid header", 0, "X-Canary", "http_x_canary", []string{"value1", "value2"}, "", "", nil, false},
		{"canary with header and empty value", 0, "X-Canary", "", []string{"value1", ""}, "", "", nil, true},
		{"canary with header and no values", 0, "X-Canary", "", []string{}, "", "", nil, true},
		{"canary with valid cookie", 0, "", "", nil, "canary_enabled", "cookie_canary_enabled", []string{"allow", "do_canary"}, false},
		{"canary with cookie and empty value", 0, "", "", nil, "canary_enabled", "", []string{"", "allow"}, true},
		{"canary with cookie and no values", 0, "", "", nil, "canary_enabled", "", []string{}, true},
	}

	for _, test := range tests {
		info := Policy{
			Header: struct {
				Name   string   `yaml:"name"`
				Values []string `yaml:"values,flow"`
			}{
				Name:   test.canaryHeader,
				Values: test.canaryHeaderValues,
			},
			Cookie: struct {
				Name   string   `yaml:"name"`
				Values []string `yaml:"values,flow"`
			}{
				Name:   test.canaryCookie,
				Values: test.canaryCookieValues,
			},
			Weigth: test.canaryWeight,
		}
		bytes, err := yaml.Marshal(info)
		data[parser.GetAnnotationWithPrefix("canary-by-policy")] = string(bytes)

		i, err := NewParser(&resolver.Mock{}).Parse(ing)
		if test.expErr {
			if err == nil {
				t.Errorf("%v: expected error but returned nil", test.title)
			}
			continue
		} else {
			if err != nil {
				t.Errorf("%v: expected nil but returned error %v", test.title, err)
			}
		}
		canaryConfig, ok := i.(*Config)
		if !ok {
			t.Errorf("%v: expected an External type", test.title)
		}
		if canaryConfig.Weight != test.canaryWeight {
			t.Errorf("%v: expected \"%v\", but \"%v\" was returned", test.title, test.canaryWeight, canaryConfig.Weight)
		}
		if canaryConfig.Header != test.canaryNginxHeader {
			t.Errorf("%v: expected \"%v\", but \"%v\" was returned", test.title, test.canaryHeader, canaryConfig.Header)
		}
		if canaryConfig.Cookie != test.canaryNginxCookie {
			t.Errorf("%v: expected \"%v\", but \"%v\" was returned", test.title, test.canaryCookie, canaryConfig.Cookie)
		}
		if !test.expErr {
			if !equals(canaryConfig.HeaderValues, test.canaryHeaderValues) {
				t.Errorf("%v: expected \"%v\", but \"%v\" was returned", test.title, test.canaryHeaderValues, canaryConfig.HeaderValues)
			}
			if !equals(canaryConfig.CookieValues, test.canaryCookieValues) {
				t.Errorf("%v: expected \"%v\", but \"%v\" was returned", test.title, test.canaryCookieValues, canaryConfig.CookieValues)
			}
		}
	}
}

// equals is duplicated in test_equals() since the right place for the method is not found yet
func equals(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}

	for i, s := range s1 {
		if s != s2[i] {
			return false
		}
	}
	return true
}

func TestBadAnnotationFormat(t *testing.T) {
	ing := buildIngress()

	data := map[string]string{}
	ing.SetAnnotations(data)

	tests := []struct {
		title  string
		policy string
	}{
		{
			title: "invalid field type",
			policy: `
weight: text
`},
		{
			title: "tabulation indent",
			policy: `
header:
	Name: abc
`},
		{
			title: "invalid indentation",
			policy: `header:
 name:
  values:
   - v1
`},
		{
			title: "invalid structure",
			policy: `
cookie:
 name: canary_enabled
 values:
  - WrongField: X
`},
	}

	for _, test := range tests {
		data[parser.GetAnnotationWithPrefix("canary-by-policy")] = test.policy
		_, err := NewParser(&resolver.Mock{}).Parse(ing)
		if err == nil || err.Error() != "the annotation canary-by-policy does not contain a valid configuration: bad YAML policy" {
			t.Errorf("%v: expected error but returned nil", test.title)
		}
	}
}
