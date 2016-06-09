package sshtool

type SshError struct {
	msg		string			// description of error
	number	int
}

func New(number int, text string) error /*SshError*/ {
	return &SshError{text, number}
}

func (e *SshError) Error() (string) { 
	return e.msg
}