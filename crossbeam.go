/*
 * Copyright (c) 2016 Michael Jacobsen (github.com/mikejac)
 *
 * This file is part of ssh.golang.
 *
 * ssh.golang is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * ssh.golang is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ssh.golang.  If not,
 * see <http://www.gnu.org/licenses/>.
 *
 */

package sshtool

import (
	"fmt"
	"strings"
	"strconv"
	"time"
    "regexp"
)

type VAPGroup struct {
	Name	string
	Count	int
}

type VAPGroups []VAPGroup

//
//
func (sshAction *SshAction) GetVAPGroups() (vapGroups VAPGroups, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): begin\n") }

	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			fallthrough

		case PlatformExpert:
			fallthrough

		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): not crossBeam\n") }
		
			return vapGroups, New(5000, "not platform xbm")

		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetGetVAPGroups(): PlatformXBM\n") }

			result, err = sshAction.execute("show vap-group", 5)
			if err != nil {
				return vapGroups, New(5000, err.Error())
			}
			
		default:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetGetVAPGroups(): unknown platform\n") }
			return vapGroups, New(5001, "platform unknown")
	}
				
	lines := strings.Split(result, "\n")
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): lines = %q\n", lines) }
	
	var vapGroup	string
	var vapCount	string
	
	// go thru each line
	for _, v := range lines {
		if strings.HasPrefix(v, "VAP Group") {
			f := strings.Split(v, ":")
			n := len(f)
			
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): n = %d, f = %q\n", n, f) }
			
			if n == 2 {
				vapGroup = strings.TrimSpace(f[1])
			
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): vapGroup = '%s'\n", vapGroup) }
			}
		} else if strings.HasPrefix(v, "VAP Count") {
			f := strings.Split(v, ":")
			n := len(f)
			
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPGroups(): n = %d, f = %q\n", n, f) }
			
			if n == 2 {
				vapCount = strings.TrimSpace(f[1])
			
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetVAPs(): vapCount = '%s'\n", vapCount) }
				
				//
				// we have the info we want from this VAP so store it
				//
				var vap VAPGroup
				vap.Name		= vapGroup
				vap.Count, _	= strconv.Atoi(vapCount)
				
				vapGroups = append(vapGroups, vap)
			}
		}
	}

	return vapGroups, nil
}

//
//
func (sshAction *SshAction) ConnectVAP(vapGroup string, member int) (err error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::ConnectVAP(): start") }

	if err = sshAction.xbmEnter(); err == nil {
		done := make(chan error, 1)
		
		go func(done chan error) {		
			buf := make([]byte, inBufferSize)
			t   := 0
			
			for {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::ConnectVAP(): start Read()\n") }
				
				n, err := sshAction.out.Read(buf[t:])
				if err != nil {
					sshAction.prompt = -1
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::ConnectVAP(): failed to read: %s\n", err.Error()) }
					
					// signal parent we're done
					done <- New(5100, err.Error())
					break
				}
							
				if n > 0 {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::ConnectVAP(): n = %d\n", n) }
	
					str := string(buf[:])
					str  = strings.TrimRight(str[0:len(str)], "\000")
					
					t += n
					if sshAction.verbose > 0 { fmt.Println("'''" + str + "'''") }
					
					if sshAction.prompt4.MatchString(str) {
						sshAction.prompt = 5
						if sshAction.verbose > 0 { fmt.Printf("SshAction::ConnectVAP(): found prompt 5\n") }
						
						if sshAction.verbose > 0 { fmt.Printf("SshAction::ConnectVAP(): n = %d\n", n) }
						
						// signal parent we're done
						done <- sshAction.findPrompt(string(buf[:]))
						break
					}
				}
			}
		}(done)
	
		vap := vapGroup + "_" + strconv.Itoa(member)
		
		sshAction.in.Write([]byte("rsh " + vap + " 2>&1\n"))
		
		/******************************************************************************************************************
		 * wait for transaction to complete or timeout
		 *
		 */
		select {
			case err = <-done:
				if sshAction.verbose > 0 { fmt.Println("SshAction::ConnectVAP(): completed") }
				break
			case <- time.After(time.Duration(promptXBMWaitTimeout) * time.Second):
				if sshAction.verbose > 0 { fmt.Println("SshAction::ConnectVAP(): timeout") }
				err = New(5101, "timeout")
				break
		}
		
	} 
	
	return err
}

//
//
func (sshAction *SshAction) DisconnectVAP() (err error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::DisconnectVAP(): start") }

	if err = sshAction.xbmExit(); err == nil {							// exit from VAP
		if err = sshAction.xbmExit(); err != nil {						// exit from CPM Linux
			return err
		}
	} else {
		return err
	}
	
	return nil
}
	
//
//
func (sshAction *SshAction) xbmEnter() (error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::xbmEnter(): start") }
	
	var err error
	done := make(chan error, 1)
	
	go func(done chan error) {		
		var psw1 *regexp.Regexp
	
		psw1 = regexp.MustCompile(`Password: `)

		buf := make([]byte, inBufferSize)
		t   := 0
		
		for {
			if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): start Read()\n") }
			
			n, err := sshAction.out.Read(buf[t:])
			if err != nil {
				sshAction.prompt = -1
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): failed to read: %s\n", err.Error()) }
				
				// signal parent we're done
				done <- New(5100, err.Error())
				break
			}
						
			if n > 0 {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): n = %d\n", n) }

				str := string(buf[:])
				str  = strings.TrimRight(str[0:len(str)], "\000")
				
				t += n
				if sshAction.verbose > 0 { fmt.Println(str) }
				
				if sshAction.prompt1.MatchString(str) {
					sshAction.prompt = 1
					if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): found prompt 1\n") }
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): n = %d\n", n) }
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				} else if sshAction.prompt2.MatchString(str) {
					sshAction.prompt = 2
					if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): found prompt 2\n") }		// 
					
					// signal parent we're done
					done <- sshAction.findPrompt(string(buf[:]))
					break
				} else if psw1.MatchString(str) {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmEnter(): found password 1\n") }
					
					t   = 0
					buf = make([]byte, inBufferSize)
					
					sshAction.in.Write([]byte(sshAction.su_passw + "\n"))
				}
			}
		}
	}(done)

	sshAction.in.Write([]byte("unix su\n"))
	
	/******************************************************************************************************************
	 * wait for transaction to complete or timeout
	 *
	 */
	select {
		case err = <-done:
			if sshAction.verbose > 0 { fmt.Println("SshAction::xbmEnter(): completed") }
			break
		case <- time.After(time.Duration(promptWaitTimeout) * time.Second):
			if sshAction.verbose > 0 { fmt.Println("SshAction::xbmEnter(): timeout") }
			err = New(5101, "timeout")
			break
	}
		
	return err
}

//
//
func (sshAction *SshAction) xbmExit() (error) {
	if sshAction.verbose > 0 { fmt.Println("SshAction::xbmExit(): start") }

	sshAction.in.Write([]byte("exit\n"))
	
	if err := sshAction.waitfor(); err != nil {
		if sshAction.verbose > 0 { fmt.Println("SshAction::xbmExit(): " + err.Error()) }
		return New(5200, "failed to locate prompt")
	}
	
	return nil
}