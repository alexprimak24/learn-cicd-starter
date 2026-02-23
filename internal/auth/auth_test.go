package auth

import "testing"

type fakeHeader map[string]string

func (f fakeHeader) Get(key string) string {
	return f[key]
}

func TestGetAPIKey(t *testing.T) {
	testKey := "ApiKey test-key"
	splittedTestKey := "test-key"

	emptryKey := ""
	wrongKey1 := "apikey test-key"
	wrongKey2 := "ApiKey"

	successHeader := fakeHeader{
		"Authorization": testKey,
	}

	emptyHeader := fakeHeader{
		"Authorization": emptryKey,
	}

	noHeader := fakeHeader{}

	wrongHeader1 := fakeHeader{
		"Authorization": wrongKey1,
	}

	wrongHeader2 := fakeHeader{
		"Authorization": wrongKey2,
	}

	tests := []struct {
		testName      string
		header        fakeHeader
		expectedError error
		expectedKey   string
	}{
		{"happy_path", successHeader, nil, splittedTestKey},
		{"empty_header", emptyHeader, ErrNoAuthHeaderIncluded, emptryKey},
		{"no_header", noHeader, ErrNoAuthHeaderIncluded, emptryKey},
		{"wrong_header_1", wrongHeader1, ErrMalformedAuthHeader, emptryKey},
		{"wrong_header_2", wrongHeader2, ErrMalformedAuthHeader, emptryKey},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			key, err := GetAPIKey(tt.header)
			if err != tt.expectedError {
				t.Fatalf("expected error %v, got %v", tt.expectedError, err)
			}
			if key != tt.expectedKey {
				t.Fatalf("expected key %v, got %v", tt.expectedKey, key)
			}
		})
	}

}
