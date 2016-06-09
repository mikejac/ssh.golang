/*
 * Copyright (c) 2016 Michael Jacobsen (github.com/mikejac)
 *
 * This file is part of <>.
 *
 * <Z is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * <> is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with <>.  If not,
 * see <http://www.gnu.org/licenses/>.
 *
 */

package sshtool

import (
	"fmt"
	"io"
	"time"
	"strings"
	"strconv"
    "regexp"
	"golang.org/x/crypto/ssh"
)

const (
	PlatformGAiA			= iota
	PlatformSplatCPSHELL	= iota
	PlatformExpert		= iota
	PlatformIPSO			= iota
	PlatformXBM			= iota
	PlatformCPM			= iota
	PlatformAPM			= iota
)

type Platform int

const (
	inBufferSize				int = 1024 * 1024
	promptWaitTimeout 		int = 5
	promptXBMWaitTimeout 	int = 20
)

type SshAction struct {
	verbose	int
	
	host		string
	user		string
	passw		string
	su_passw	string
	port		int
	
	client		*ssh.Client
	session	*ssh.Session
	in			io.WriteCloser
	out			io.Reader
	err			io.Reader

	prompt1 	*regexp.Regexp
	prompt2 	*regexp.Regexp
	prompt3 	*regexp.Regexp
	prompt4 	*regexp.Regexp
	
	currentPrompt	string
	
	prompt			int
	splat 			bool
	splat_cpshell	bool
	xbm				bool
	ipso			bool
	
	platform		Platform
}

func NewSshAction(host string, user string, passw string, su_passw string, port int, verbose int) (sshAction *SshAction, err error) {
	cc := &ssh.Config{
		Ciphers: []string{"aes256-ctr", "aes128-cbc", "hmac-sha1", "none"},
	}
	
	config := &ssh.ClientConfig{
		Config: *cc,
	    User: user,
	    Auth: []ssh.AuthMethod{
	        ssh.Password(passw),
	    },
	}
	
	client, err := ssh.Dial("tcp", host + ":" + strconv.Itoa(port), config)
	if err != nil {
		//fmt.Println("NewSshAction(): could not connect to host: " + err.Error())
		return nil, err
	}

	sshAction = &SshAction{
		verbose:	verbose,
		host:		host,
		user:		user,
		passw:		passw,
		su_passw:	su_passw,
		port:		port,
		client:	client,
		prompt:	-1,
	}
		
	sshAction.prompt1 = regexp.MustCompile(`\w> `)						// GAIA CLISH
	sshAction.prompt2 = regexp.MustCompile(`\w]# `)						// Expert or SPLAT CPSHELL or IPSO
	sshAction.prompt3 = regexp.MustCompile(`\w# `)						// CrossBeam CPM
	sshAction.prompt4 = regexp.MustCompile(`\w] ~\$ `)					// CrossBeam APM

	return sshAction, nil
}

//
//
func (sshAction *SshAction) Connect() (error) {
	session, err := sshAction.client.NewSession()
	if err != nil {
		return New(1000, err.Error())
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
	}
	
	// request pseudo terminal
	if err := session.RequestPty("vt100", 256, 4096, modes); err != nil {
		session.Close()
		return New(1001, err.Error())
	}		

	sshAction.in, err = session.StdinPipe()
	if err != nil {
		session.Close()
		return New(1002, err.Error())
	}

	sshAction.out, err = session.StdoutPipe()
	if err != nil {
		session.Close()
		return New(1003, err.Error())
	}

	sshAction.err, err = session.StderrPipe()
	if err != nil {
		session.Close()
		return New(1004, err.Error())
	}

	err = session.Shell()
	if err != nil {
		session.Close()
		return New(1005, err.Error())
	}

	err = sshAction.waitfor()
	if err != nil {
		session.Close()
		return New(1006, err.Error())
	}
	
	sshAction.session = session
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::Connect(): prompt = %d\n", sshAction.prompt) }
	
	return sshAction.detect()
}

//
//
func (sshAction *SshAction) Exit() (error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::Exit(): begin\n") }

	sshAction.in.Write([]byte("exit\n"))
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::Exit(): end\n") }

	return nil
}

//
//
func (sshAction *SshAction) Disconnect() (error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::Disconnect(): begin\n") }

	sshAction.session.Close()
	sshAction.client.Close()
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::Disconnect(): end\n") }

	return nil
}

//
//
func (sshAction *SshAction) detect() (error) {
	ok := false
	
	if sshAction.prompt == 1 {
		if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): GAiA CLISH") }
		
		ok						= true
		sshAction.platform	= PlatformGAiA
	} else if sshAction.prompt == 2 {
		if sshAction.splat == true && sshAction.splat_cpshell == true {
			if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): SPLAT CPSHELL") }
			
			ok						= true
			sshAction.platform	= PlatformSplatCPSHELL
		} else {
			if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): Expert-mode") }
			
			ok						= true
			sshAction.platform	= PlatformExpert
		}
	} else if sshAction.prompt == 3 {
		if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): XBM") }
		
		ok						= true
		sshAction.platform	= PlatformXBM
	} else if sshAction.prompt == 4 {
		if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): IPSO") }
		
		ok						= true
		sshAction.platform	= PlatformIPSO
	} else if sshAction.prompt == 5 {
		if sshAction.verbose > 0 { fmt.Println("SshAction::detect(): XBM APM") }
		
		ok						= true
		sshAction.platform	= PlatformXBM
	}

	if ok {
		return nil
	}	
	
	return New(1100, "failed to detect platform")
}

//
//
func (sshAction *SshAction) expertEnter() (error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::expertEnter(): start") }
	
	var err error
	done := make(chan error, 1)
	
	go func(done chan error) {		
		var psw1 *regexp.Regexp
	
		psw1	= regexp.MustCompile(` expert password:`)

		buf := make([]byte, inBufferSize)
		t   := 0
		
		for {
			if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): start Read()\n") }
			
			n, err := sshAction.out.Read(buf[t:])
			if err != nil {
				sshAction.prompt = -1
				
				//fmt.Printf("SshAction::expertEnter(): failed to read: %s\n", err.Error())
				
				// signal parent we're done
				done <- New(1200, err.Error())
				break
			}
						
			if n > 0 {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): n = %d\n", n) }
				
				t += n
				if sshAction.verbose > 0 { fmt.Println(string(buf[:])) }
				
				if sshAction.prompt1.MatchString(string(buf[:])) {
					sshAction.prompt = 1
					if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): found prompt 1\n") }
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): n = %d\n", n) }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				} else if sshAction.prompt2.MatchString(string(buf[:])) {
					sshAction.prompt = 2
					if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): found prompt 2\n") }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				} else if psw1.MatchString(string(buf[:])) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::expertEnter(): found password 1\n") }
					
					t   = 0
					buf = make([]byte, inBufferSize)
					
					sshAction.in.Write([]byte(sshAction.su_passw + "\n"))
				}
			}
		}
	}(done)

	sshAction.in.Write([]byte("expert\n"))
	
	/******************************************************************************************************************
	 * wait for transaction to complete or timeout
	 *
	 */
	select {
		case err = <-done:
			if sshAction.verbose > 0 { fmt.Println("SshAction::expertEnter(): completed succefully") }
			break
		case <- time.After(time.Duration(promptWaitTimeout) * time.Second):
			if sshAction.verbose > 0 { fmt.Println("SshAction::expertEnter(): timeout") }
			err = New(1201, "timeout")
			break
	}
		
	return err
}

//
//
func (sshAction *SshAction) expertExit() (error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::expertExit(): start") }

	sshAction.in.Write([]byte("exit\n"))
	
	if err := sshAction.waitfor(); err != nil {
		if sshAction.verbose > 0 { fmt.Println("SshAction::expertExit(): " + err.Error()) }
		return New(1301, "failed to locate prompt")
	}
	
	return nil
}

//
//	
func (sshAction *SshAction) waitfor() (error) {
	var err error
	
	done := make(chan error, 1)
	
	go func(done chan error) {		
		var hint1 *regexp.Regexp
		var hint2 *regexp.Regexp
		var hint3 *regexp.Regexp
		var hint4 *regexp.Regexp
	
		hint1 = regexp.MustCompile(`\\? for list of commands`)			// SPLAT CPSHELL
		hint2 = regexp.MustCompile(`Active Alarms Summary`)				// CrossBeam
		hint3 = regexp.MustCompile(`IPSO `)								// IPSO
		hint4 = regexp.MustCompile(`Terminal type\\?`)					// IPSO
		
		buf := make([]byte, inBufferSize)
		t   := 0
		
		if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): start wait\n") }
		
		for {
			n, err := sshAction.out.Read(buf[t:])
			if err != nil {
				sshAction.prompt = -1
				
				//fmt.Printf("SshAction::waitfor(): failed to read: %s\n", err.Error())
				
				// signal parent we're done
				done <- New(1400, err.Error())
				break
			}
			
			if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): n = %d\n", n) }
			
			if n > 0 {
				str := string(buf[:])
				str  = strings.TrimRight(str[0:len(str)], "\000")
				
				t += n
				//if sshAction.verbose > 0 { fmt.Println(string(buf[:])) }
				if sshAction.verbose > 0 { fmt.Println(str) }
				
				//if sshAction.prompt1.MatchString(string(buf[:])) {
				if sshAction.prompt1.MatchString(str) {
					sshAction.prompt = 1
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found prompt 1\n") }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				//} else if sshAction.prompt2.MatchString(string(buf[:])) {
				} else if sshAction.prompt2.MatchString(str) {
					if sshAction.ipso {
						sshAction.prompt = 4
						if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found prompt 4\n") }						
					} else {
						sshAction.prompt = 2
						if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found prompt 2\n") }
					}
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				//} else if sshAction.prompt3.MatchString(string(buf[:])) {
				} else if sshAction.prompt3.MatchString(str) {
					sshAction.prompt = 3
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found prompt 3\n") }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				//} else if hint1.MatchString(string(buf[:])) {
				} else if sshAction.prompt4.MatchString(str) {
					sshAction.prompt = 5
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found prompt 5\n") }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				} else if hint1.MatchString(str) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found hint 1\n") }

					sshAction.splat         = true
					sshAction.splat_cpshell = true					
				//} else if hint2.MatchString(string(buf[:])) {
				} else if hint2.MatchString(str) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found hint 2\n") }

					sshAction.xbm = true
				//} else if hint3.MatchString(string(buf[:])) {
				} else if hint3.MatchString(str) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found hint 3\n") }

					t   = 0
					buf = make([]byte, inBufferSize)
					
					sshAction.ipso = true
				//} else if hint4.MatchString(string(buf[:])) {
				} else if hint4.MatchString(str) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::waitfor(): found hint 4\n") }

					t   = 0
					buf = make([]byte, inBufferSize)
					
					sshAction.in.Write([]byte("vt220\n"))
				}
			}
		}
	}(done)
	
	/******************************************************************************************************************
	 * wait for transaction to complete or timeout
	 *
	 */
	select {
		case err = <-done:
			if sshAction.verbose > 0 { fmt.Println("SshAction::waitfor(): completed succefully") }
			break
		case <- time.After(time.Duration(promptWaitTimeout) * time.Second):
			if sshAction.verbose > 0 { fmt.Println("SshAction::waitfor(): timeout") }
			err = New(1401, "timeout")
			break
	}
		
	return err
}

//
//
func (sshAction *SshAction) findPrompt(str string) (error) {
	if sshAction.ipso {
		str = "\n" + str
	}
	
	n := strings.LastIndex(str, "\n")
	
	if n < 0 {
		if sshAction.verbose > 0 { fmt.Printf("SshAction::findPrompt(): newline not found\n") }	
		return New(1500, "newline not found")
	}
	
	sshAction.currentPrompt = strings.TrimRight(str[n:len(str)], "\000")
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::findPrompt(): n = %d, currentPrompt = '%s'\n", n, sshAction.currentPrompt) }
			
	return nil
}

//
//
func (sshAction *SshAction) execute(cmd string, timeout int) (result string, err error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::execute(): start") }

	cmd   = cmd + "\n"
	done := make(chan error, 1)

	if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): sshAction.currentPrompt = '%s'", sshAction.currentPrompt) }
	if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): cmd = '%s'", cmd) }
	
	go func(done chan error, cmd string) {		
		buf := make([]byte, 1)
		idx := 0
		t   := 0
		
		for {
			n, err := sshAction.out.Read(buf[t:])
			if err != nil {
				//sshAction.prompt = -1
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): failed to read: %s\n", err.Error()) }
				
				// signal parent we're done
				done <- New(1600, err.Error())
				break
			}
			
			//if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): n = %d\n", n) }
			
			if n == 1 && t == 0 {
				// 'eat' the echo of our command
				if buf[0] == cmd[idx] {
					//if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): buf[0] == cmd[idx] (%c)\n", cmd[idx]) }

					if cmd[idx] == '\n' {
						// echo of command done - increase read buffer
						buf = make([]byte, inBufferSize)

						if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): done reading command echo\n") }
					} else {
						idx++
					}
				} else {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): buf[0] = %02X, cmd[idx] = %c\n", buf[0], cmd[idx]) }					
				}
			} else if n > 0 {
				t += n
				
				str := string(buf[:])
				str  = strings.TrimRight(str[0:len(str)], "\000")
				
				if sshAction.verbose > 0 { fmt.Println("SshAction::execute(): buf[:] = " + str) }
				
				//if strings.Contains(string(buf[:]), sshAction.currentPrompt) {
				if strings.Contains(str, sshAction.currentPrompt) {
					// remove (trailing) prompt from result
					result = string(buf[0:strings.Index(string(buf[:]), sshAction.currentPrompt)])
					result = strings.TrimRight(result, "\000")
					
					//if sshAction.verbose > 0 { fmt.Printf("SshAction::execute(): found current prompt; len(buf) = %d, len(sshAction.currentPrompt) = %d\n", len(string(buf[:])), len(sshAction.currentPrompt)) }
					
					// signal parent we're done
					done <- nil
					break
				}
			}
		}
	}(done, cmd)

	sshAction.in.Write([]byte(cmd))

	/******************************************************************************************************************
	 * wait for transaction to complete or timeout
	 *
	 */
	select {
		case err = <-done:
			if sshAction.verbose > 0 { fmt.Println("SshAction::execute(): completed succefully") }
			break
		case <- time.After(time.Duration(timeout) * time.Second):
			if sshAction.verbose > 0 { fmt.Println("SshAction::execute(): timeout") }
			err = New(1601, "timeout")
			break
	}
	
	return result, err
}
