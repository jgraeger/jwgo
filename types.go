package jwgo

import "encoding/json"

// ClaimStrings is a slice of strings. It can be serialized and decoded from either
// an string array or a single string, which will become the single element of the
// resulting slice. This is necessary for the `aud` claim.
type ClaimStrings []string

func (s *ClaimStrings) UnmarshalJSON(data []byte) error {
	// To speed things up, we first check if the passed data appears to be a string or an array.
	// We call the serialization function directly, if it is a string or an array.
	// If it succeeds, we can skip the Unmarshal call against an empty interface
	switch {
	case likelyContainsArray(data):
		var arr []string
		if err := json.Unmarshal(data, &arr); err == nil {
			*s = ClaimStrings(arr)
			return nil
		}
	case likelyContainsString(data):
		var str string
		if err := json.Unmarshal(data, &str); err == nil {
			*s = ClaimStrings([]string{str})
			return nil
		}
	}

	// If the above failed, we decode against an empty interface
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	var aud []string

	switch v := v.(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = ClaimStrings(v)
	case []any:
		for i := range v {
			str, ok := v[i].(string)
			if !ok {
				return ErrInvalidType
			}
			aud = append(aud, str)
		}
	case nil:
		return nil
	default:
		return ErrInvalidType
	}

	*s = ClaimStrings(aud)
	return nil
}

func likelyContainsArray(b []byte) bool {
	return b[0] == byte('[')
}

func likelyContainsString(b []byte) bool {
	return b[0] == byte('"')
}
