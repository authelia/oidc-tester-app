package main

import (
	"strings"
)

func isStringInSlice(s string, slice []string) bool {
	for _, x := range slice {
		if s == x {
			return true
		}
	}

	return false
}

func filterText(input string, filters []string) (output string) {
	if len(filters) == 0 {
		return input
	}

	for _, filter := range filters {
		input = strings.Replace(input, filter, strings.Repeat("*", len(filter)), -1)
	}

	return input
}

func filterSliceOfText(input []string, filters []string) (output []string) {
	for _, item := range input {
		output = append(output, filterText(item, filters))
	}

	return output
}
