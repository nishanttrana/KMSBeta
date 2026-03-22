package main

import "net/http"

type serviceError struct {
	status  int
	code    string
	message string
}

func (e serviceError) Error() string {
	if e.message != "" {
		return e.message
	}
	if e.code != "" {
		return e.code
	}
	return "service error"
}

func newServiceError(status int, code string, message string) error {
	return serviceError{status: status, code: code, message: message}
}

func httpStatusForErr(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if se, ok := err.(serviceError); ok && se.status > 0 {
		return se.status
	}
	return http.StatusBadRequest
}

func serviceCode(err error, fallback string) string {
	if err == nil {
		return fallback
	}
	if se, ok := err.(serviceError); ok && se.code != "" {
		return se.code
	}
	if fallback != "" {
		return fallback
	}
	return "request_failed"
}
