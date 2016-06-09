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
)

type OsClass int
type OsType  int

const (
	OsClassNone		OsClass = 0
	OsClassIPSO		OsClass = 1
	OsClassSOLARIS	OsClass = 2
	OsClassSPLAT		OsClass = 3
	OsClassGAIA		OsClass = 4
	OsClassXBM			OsClass = 5
	
	OsTypeNone      	OsType = 0
	OsTypeIPSO3_6   	OsType = 1
	OsTypeIPSO3_7   	OsType = 2
	OsTypeIPSO3_8   	OsType = 3
	OsTypeSOLARIS   	OsType = 11
	OsTypeR55       	OsType = 21
	OsTypeR65_2_4   	OsType = 22
	OsTypeR65_2_6   	OsType = 23
	OsTypeR70_1     	OsType = 24
	OsTypeR77_20		OsType = 25
	OsTypeXOS			OsType = 50
)

//
//
func (sshAction *SshAction) GetOS() (osclass OsClass, ostype OsType, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): begin\n") }

	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): PlatformGAiA or PlatformSplatCPSHELL\n") }
					
			if sshAction.expertEnter() == nil {
				result, err = sshAction.execute("uname -r 2>&1", 5)
				if err == nil {
					result = strings.TrimSpace(result)
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): result = %s\n", result) }					
				}
			
				sshAction.expertExit()
			}
		
		case PlatformExpert:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): PlatformExpert\n") }

			result, err = sshAction.execute("uname -r 2>&1", 5)
			if err == nil {
				result = strings.TrimSpace(result)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): result = %s\n", result) }					
			}
		
		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): PlatformIPSO\n") }

			result, err = sshAction.execute("uname -r", 5)
			if err == nil {
				result = strings.TrimSpace(result)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): result = %s\n", result) }					
			}
		
		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): PlatformXBM\n") }
			
			osclass, ostype, err = sshAction.xbmGetInfo()
			
			return osclass, ostype, err
			
		default:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): unknown platform\n") }
			return OsClassNone, OsTypeNone, New(2001, "platform unknown")
	}
	
	if strings.Contains(result, "2.4.21-21cp") {
		osclass = OsClassSPLAT
		ostype  = OsTypeR65_2_4
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeR65_2_4") }
	} else if strings.Contains(result, "2.4.21-21cpsmp") {
		osclass = OsClassSPLAT
		ostype  = OsTypeR65_2_4
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeR65_2_4") }
	} else if strings.Contains(result, "2.6.18-22cp") {
		osclass = OsClassSPLAT
		ostype  = OsTypeR65_2_6
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeR65_2_6") }
	} else if strings.Contains(result, "2.6.18-92cp") {
		osclass = OsClassSPLAT
		ostype  = OsTypeR70_1
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeR70_1") }
	} else if strings.Contains(result, "2.4.9-42cp") {
		osclass = OsClassSPLAT
		ostype  = OsTypeR55	
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeR55") }
	} else if strings.Contains(result, "3.8") {
		osclass = OsClassIPSO
		ostype  = OsTypeIPSO3_8
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeIPSO3_8") }
	} else if strings.Contains(result, "3.7") {
		osclass = OsClassIPSO
		ostype  = OsTypeIPSO3_7
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeIPSO3_7") }
	} else if strings.Contains(result, "3.6") {
		osclass = OsClassIPSO
		ostype  = OsTypeIPSO3_6
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeIPSO3_6") }
	} else if strings.Contains(result, "5.8") {
		osclass = OsClassSOLARIS
		ostype  = OsTypeSOLARIS
		if sshAction.verbose >= 1 { fmt.Println("SshAction::GetOS(): OsTypeSOLARIS") }
	} else if strings.Contains(result, "Running commands is not allowed") {
		if sshAction.verbose > 0 { fmt.Println("SshAction::GetOS(): none; running commands is not allowed") }
		err = New(2002, "running commands is not allowed")
	} else {
		err = New(2003, "unexpected")
		if sshAction.verbose > 0 { fmt.Println("SshAction::GetOS(): unknown") }
	}
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetOS(): end\n") }					

	return osclass, ostype, err
}

//
//
func (sshAction *SshAction) GetInfo() (fwver string, platform string, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): begin\n") }

	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): PlatformGAiA or PlatformSplatCPSHELL\n") }
					
			if sshAction.expertEnter() == nil {
				result, err = sshAction.execute("fw ver 2>&1", 20)
				if err == nil {
					fwver = strings.TrimSpace(result)
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): result = %s\n", fwver) }					
				}
			
				result, err = sshAction.execute("cat /etc/cp-release 2>&1", 20)
				if err == nil {
					platform = strings.TrimSpace(result)
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): result = %s\n", platform) }					
				}

				sshAction.expertExit()
			}
		
		case PlatformExpert:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): PlatformExpert\n") }

			result, err = sshAction.execute("fw ver 2>&1", 20)
			if err == nil {
				fwver = strings.TrimSpace(result)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): result = %s\n", fwver) }					

				result, err = sshAction.execute("cat /etc/cp-release 2>&1", 20)
				if err == nil {
					platform = strings.TrimSpace(result)
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): result = %s\n", platform) }					
				}
			}
		
		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): PlatformIPSO\n") }

			result, err = sshAction.execute("fw ver", 20)
			if err == nil {
				fwver = strings.TrimSpace(result)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): result = %s\n", fwver) }					
			}
			
			platform = "IPSO"
		
		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): PlatformXBM\n") }
			return "", "", New(2100, "platform xbm")
			
		default:
			fmt.Printf("SshAction::GetInfo(): unknown platform\n")
			return "", "", New(2101, "platform unknown")
	}
	
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInfo(): end\n") }					

	return fwver, platform, err
}

//
//
func (sshAction *SshAction) xbmGetInfo() (osclass OsClass, ostype OsType, err error) {
	var result string
	
	result, err = sshAction.execute("show version", 5)
	if err == nil {
		lines := strings.Split(result, "\n")
		
		if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmGetInfo(): lines = %q\n", lines) }
		
		// go thru each line
		for _, v := range lines {
			if strings.Contains(v, "Version:") {
				f := strings.Fields(v)
				n := len(f)
				
				if n >= 3 && f[1] == "XOS" {
					osclass	= OsClassXBM
					ostype		= OsTypeXOS
					
					break
				} else {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::xbmGetInfo(): invalid version string\n") }
					
					return osclass, ostype, New(2200, "invalid version string")
				}
			}
		}
	}

	return osclass, ostype, err
}