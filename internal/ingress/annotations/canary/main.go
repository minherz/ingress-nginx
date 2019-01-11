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
	"regexp"
	"strings"

	extensions "k8s.io/api/extensions/v1beta1"

	yaml "gopkg.in/yaml.v2"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/errors"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

type canary struct {
	r resolver.Resolver
}

var (
	headerRegexp = regexp.MustCompile(`^[a-zA-Z\d\-_]+$`)
)

// Policy public struct for parsing `canary-by-policy` YAML data
// struct fields have to be public in order for yaml.Unmarshal to populate them correctly
type Policy struct {
	Header struct {
		Name   string   `yaml:"name"`
		Values []string `yaml:"values,flow"`
	}
	Cookie struct {
		Name   string   `yaml:"name"`
		Values []string `yaml:"values,flow"`
	}
	Weigth int `yaml:"weight"`
}

// Config returns the configuration rules for setting up the Canary
type Config struct {
	Header       string
	HeaderValues []string
	Cookie       string
	CookieValues []string
	Weight       int
}

// NewParser parses the ingress for canary related annotations
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return canary{r}
}

// Parse parses the annotations contained in the ingress
// rule used to indicate if the canary should be enabled and with what config
func (c canary) Parse(ing *extensions.Ingress) (interface{}, error) {
	config := &Config{}
	var err error
	var predicate string

	predicate, err = parser.GetStringAnnotation("canary-by-policy", ing)
	if err != nil {
		return config, nil
	}
	policy := Policy{}
	err = yaml.Unmarshal([]byte(predicate), &policy)
	if err != nil {
		return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "bad YAML policy")
	}
	if policy.Header.Name != "" {
		if len(policy.Header.Values) == 0 || !headerRegexp.MatchString(policy.Header.Name) {
			return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "invalid canary header policy")
		}
		for _, v := range policy.Header.Values {
			if v == "" {
				return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "empty header value")
			}
		}
		// convert to nginx syntax
		config.Header = "http_" + strings.Replace(strings.ToLower(policy.Header.Name), "-", "_", -1)
		config.HeaderValues = policy.Header.Values
	}
	if policy.Cookie.Name != "" {
		if len(policy.Cookie.Values) == 0 || !headerRegexp.MatchString(policy.Cookie.Name) {
			return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "invalid canary cookie policy")
		}
		for _, v := range policy.Cookie.Values {
			if v == "" {
				return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "empty cookie value")
			}
		}
		// convert to nginx syntax
		config.Cookie = "cookie_" + strings.Replace(strings.ToLower(policy.Cookie.Name), "-", "_", -1)
		config.CookieValues = policy.Cookie.Values
	}
	if policy.Weigth < 0 || policy.Weigth > 100 {
		return nil, errors.NewInvalidAnnotationConfiguration("canary-by-policy", "invalid weight policy")
	}
	config.Weight = policy.Weigth
	return config, nil
}
