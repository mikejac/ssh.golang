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

type CphaData struct {
	Status	string
}

func (sshAction *SshAction) GetCPHA() (cpha *CphaData, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): begin\n") }
	
	cpha = &CphaData{}
	
	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): PlatformGAiA or PlatformSplatCPSHELL\n") }
					
			if sshAction.expertEnter() == nil {
				result, err = sshAction.execute("cphaprob stat 2>&1", 10)
				if err != nil {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): unable to execute 'cphaprob stat 2>&1'\n") }
				}
			
				sshAction.expertExit()
			}
		
		case PlatformExpert:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): PlatformExpert\n") }

			result, err = sshAction.execute("cphaprob stat 2>&1", 10)
			if err != nil {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): unable to execute 'cphaprob stat 2>&1'\n") }
			}
		
		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): PlatformIPSO\n") }

			result, err = sshAction.execute("cphaprob stat", 10)
			if err != nil {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): unable to execute 'cphaprob stat'\n") }
			}
		
		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): PlatformXBM\n") }
			
			return cpha, nil
			//return nil, New(4000, "platform XBM")
			
		default:
			fmt.Printf("SshAction::GetCPHA(): unknown platform\n")
			return nil, New(4001, "platform unknown")
	}
	
	if err != nil {
		return nil, New(4002, err.Error())
	}

	lines := strings.Split(result, "\n")
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): lines = %q\n", lines) }
	
	// go thru each line
	for _, v := range lines {
		if strings.Contains(v, "not started") {
			cpha.Status = "not_started"
			
			break
		} else if strings.Contains(v, "(local)") {
			f := strings.Fields(v)
			n := len(f)
			
			cpha.Status = strings.ToLower(f[n - 1])

			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): Status = %s\n", cpha.Status) }
			
			break
		}
	}
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetCPHA(): end\n") }
	
	return cpha, nil
}