package utils

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major, Minor, Patch int
}

func ParseVersion(v string) (Version, error) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return Version{}, fmt.Errorf("invalid version: %s", v)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return Version{}, err
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return Version{}, err
	}
	patch, err := strconv.Atoi(strings.SplitN(parts[2], "-", 2)[0])
	if err != nil {
		return Version{}, err
	}
	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

func (v Version) LessThan(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

func (v Version) LessOrEqual(other Version) bool {
	return v == other || v.LessThan(other)
}

func (v Version) GreaterOrEqual(other Version) bool {
	return !v.LessThan(other)
}

// InRange checks if version is in range string like "[2.5.0,2.5.12)" or "(,2.6.4]"
func InRange(version, rangeStr string) bool {
	v, err := ParseVersion(version)
	if err != nil {
		return false
	}
	rangeStr = strings.TrimSpace(rangeStr)
	if len(rangeStr) < 3 {
		return false
	}

	startInclusive := rangeStr[0] == '['
	endInclusive := rangeStr[len(rangeStr)-1] == ']'
	inner := rangeStr[1 : len(rangeStr)-1]
	parts := strings.SplitN(inner, ",", 2)
	if len(parts) != 2 {
		return false
	}

	low := strings.TrimSpace(parts[0])
	high := strings.TrimSpace(parts[1])

	if low != "" {
		lowV, err := ParseVersion(low)
		if err != nil {
			return false
		}
		if startInclusive && v.LessThan(lowV) {
			return false
		}
		if !startInclusive && v.LessOrEqual(lowV) {
			return false
		}
	}

	if high != "" {
		highV, err := ParseVersion(high)
		if err != nil {
			return false
		}
		if endInclusive && highV.LessThan(v) {
			return false
		}
		if !endInclusive && highV.LessOrEqual(v) {
			return false
		}
	}
	return true
}
