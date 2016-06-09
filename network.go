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
	"sort"
	"net"
)

//
//
type NetworkLogicalInterface struct {
	IfName	string
	IfIP	string
	Addr	net.IP
	Mask	net.IPMask
}

type LogicalInterfaces []NetworkLogicalInterface

//
//
type NetworkPhysicalInterface struct {
	IfName	string
	VLAN	string
}

type PhysicalInterfaces []NetworkPhysicalInterface

//
//
type NetworkRoute struct {
	Net			string
	Gateway	string
	Dev			string
	IPNet		net.IPNet
}

type Routes []NetworkRoute

//
//
func (sshAction *SshAction) GetInterfaces() (logical LogicalInterfaces, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): begin\n") }

	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): PlatformGAiA or PlatformSplatCPSHELL\n") }
					
			if sshAction.expertEnter() == nil {
				result, err = sshAction.execute("ip -o -f inet addr 2>&1", 10)
				if err != nil {
					if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): unable to execute 'ip -o -f inet addr 2>&1'\n") }
				}
			
				sshAction.expertExit()
			}
		
		case PlatformExpert:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): PlatformExpert\n") }

			result, err = sshAction.execute("ip -o -f inet addr 2>&1", 10)
			if err != nil {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): unable to execute 'ip -o -f inet addr 2>&1'\n") }
			}
		
		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): PlatformIPSO\n") }

			result, err = sshAction.execute("ifconfig -a", 10)
			if err != nil {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): unable to execute 'ifconfig -a'\n") }
			} else {
				var physical PhysicalInterfaces
				
				err = sshAction.ipsoInterfaces(result, &logical, &physical)
			}

			sort.Sort(logical)
	
			return logical, err
		
		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): PlatformXBM\n") }
			
			return logical, nil
			//return nil, New(3000, "platform XBM")
			
		default:
			fmt.Printf("SshAction::GetInterfaces(): unknown platform\n")
			return nil, New(3001, "platform unknown")
	}
	
	if err != nil {
		return nil, New(3002, err.Error())
	}
	
	lines := strings.Split(result, "\n")
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): lines = %q\n", lines) }
	
	// go thru each line
	for _, v := range lines {
		f := strings.Fields(v)
		n := len(f)

		if n > 2 {
			if !strings.HasPrefix(f[1], "lo") {
				if n > 4 {
					a  := strings.Split(f[3], "/")
					
					addr := net.ParseIP(a[0])
   					if addr == nil {
						fmt.Printf("SshAction::GetInterfaces(): invalid address '%s'\n", v)				
   					} else {
						var ni NetworkLogicalInterface
						ni.IfName = f[1]
						ni.IfIP   = f[3]
						ni.Addr   = addr

						if len(a) == 2 {
							m, _    := strconv.Atoi(a[1])
							ni.Mask  = net.CIDRMask(m, 32)
						} else {
							ni.Mask  = net.CIDRMask(32, 32)
						}
						
						logical = append(logical, ni)
												
						if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetInterfaces(): ifname = '%s', ip = '%s'\n", ni.IfName, ni.IfIP) }
					}
				} else {
					fmt.Printf("SshAction::GetInterfaces(): invalid address '%s'\n", v)
				}
			}
		} else {
			fmt.Printf("SshAction::GetInterfaces(): invalid address '%s'\n", v)
		}
	}
	
	sort.Sort(logical)
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetInterfaces(): end\n") }
	
	return logical, nil
}

//
// 3100
func (sshAction *SshAction) GetPhyInterfaces(logical LogicalInterfaces) (physical PhysicalInterfaces, err error) {
	for _, i := range logical {
		p := strings.Split(i.IfName, ".")
		
		if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetPhyInterfaces(): ifname = '%s', ip = '%s', len(p) = %d\n", i.IfName, i.IfIP, len(p)) }

		var ni NetworkPhysicalInterface
		
		if len(p) == 1 {
			ni.IfName = p[0]
			physical = append(physical, ni)
		} else if len(p) == 2 {
			ni.IfName = p[0]
			ni.VLAN   = p[1]
			physical = append(physical, ni)
		} else {
			fmt.Printf("SshAction::GetPhyInterfaces(): invalid interface '%s'\n", i.IfName)						
		}
	}

	sort.Sort(physical)

	if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetPhyInterfaces(): physical = '%q'\n", physical) }

	return physical, nil

}

//
// 3200
func (sshAction *SshAction) GetRoutes() (routes Routes, err error) {
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): begin\n") }

	var result string
	
	switch sshAction.platform {
		case PlatformGAiA:
			fallthrough
			
		case PlatformSplatCPSHELL:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): PlatformGAiA or PlatformSplatCPSHELL\n") }
					
			if sshAction.expertEnter() == nil{
				result, err = sshAction.execute("ip -o -f inet route 2>&1", 10)
				if err != nil {
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetRoutes(): unable to execute 'ip -o -f inet route 2>&1'\n") }
				}
			
				sshAction.expertExit()
			}
		
		case PlatformExpert:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): PlatformExpert\n") }

			result, err = sshAction.execute("ip -o -f inet route 2>&1", 10)
			if err != nil {
				if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetRoutes(): unable to execute 'ip -o -f inet route 2>&1'\n") }
			}
		
		case PlatformIPSO:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): PlatformIPSO\n") }
			
			result, err = sshAction.execute("netstat -rn|grep ' CU '|grep -v '::'", 10)
			if err != nil {
				fmt.Printf("SshAction::GetInterfaces(): unable to execute 'netstat -rn|grep ' CU '|grep -v '::''\n")
			} else {
				err = sshAction.ipsoRoutes(result, &routes)
			}

			sort.Sort(routes)
	
			return routes, err
		
		case PlatformXBM:
			if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): PlatformXBM\n") }
			
			return routes, nil
			//return nil, New(3200, "platform XBM")
			
		default:
			fmt.Printf("SshAction::GetRoutes(): unknown platform\n")
			return nil, New(3201, "platform unknown")
	}
	
	if err != nil {
		return nil, New(3202, err.Error())
	}

	lines := strings.Split(result, "\n")
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): lines = %q\n", lines) }
	
	// go thru each line
	for _, v := range lines {
		f := strings.Fields(v)
		n := len(f)

		if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): n = %d, f = %q\n", n,f) }
		
		if (n == 5 || n == 7) && f[1] == "via" && f[3] == "dev" {
			if sshAction.verbose >= 1 { fmt.Printf("'%s' -> '%s'\n", f[0], f[2]) }
			
			a  := strings.Split(f[0], "/")
		
			if len(a) == 1 {
				if f[0] != "default" {
					f[0] = f[0] + "/32"
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetRoutes(): (host-route) '%s' -> '%s'\n", f[0], f[2]) }
				} else {
					f[0] = "0.0.0.0/0"
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::GetRoutes(): (default) '%s' -> '%s'\n", f[0], f[2]) }
				}
			}
			
			var n NetworkRoute
			n.Net     = f[0]
			n.Gateway = f[2]
			n.Dev     = f[4]
			
			_, ipnet, err := net.ParseCIDR(f[0])
			if err != nil {
				fmt.Printf("SshAction::GetRoutes(): %q -- %d\n", f, n)
				fmt.Printf("SshAction::GetRoutes(): '%s' -> '%s'\n", f[0], f[2])
    			fmt.Printf("SshAction::GetRoutes(): invalid network: %s" + err.Error())
				
				return nil, New(3202, err.Error())
			} else {
				n.IPNet = *ipnet
				
				routes = append(routes, n)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): %s / %s -> %s\n", n.IPNet.IP.String(), n.IPNet.Mask.String(), n.Gateway) }
			}
		}
	}
	
	sort.Sort(routes)
	
	if sshAction.verbose > 0 { fmt.Printf("SshAction::GetRoutes(): end\n") }
	
	return routes, nil
}

/******************************************************************************************************************
* IPSO functions
*
*/

//
// 3800
func (sshAction *SshAction) ipsoInterfaces(result string, logical *LogicalInterfaces, physical *PhysicalInterfaces) (err error) {
	lines := strings.Split(result, "\n")

	var name	string
	var phys	string
	var ip		string
	var up		bool
	var vlan	string
	
	// go thru each line
	for _, v := range lines {
		if v[0] != '\t' && v[0] != ' ' {									// start of interface data
			if ip != "" && up && phys != "" {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): done; phys = '%s', vlan = '%s', ip = %s\n", phys, vlan, ip) }

				a  := strings.Split(ip, "/")
				
				addr := net.ParseIP(a[0])
 				if addr == nil {
					fmt.Printf("SshAction::ipsoInterfaces(): invalid address '%s'\n", ip)				
 				} else {
					var ni NetworkLogicalInterface
					
					if vlan == "" {
						ni.IfName = phys
					} else {
						ni.IfName = phys + "." + vlan
					}
					
					ni.IfIP   = ip
					ni.Addr   = addr
	
					if len(a) == 2 {
						m, _    := strconv.Atoi(a[1])
						ni.Mask  = net.CIDRMask(m, 32)
					} else {
						ni.Mask  = net.CIDRMask(32, 32)
					}
					
					*logical = append(*logical, ni)
											
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoInterfaces(): ifname = '%s', ip = '%s'\n", ni.IfName, ni.IfIP) }
				}

				var np NetworkPhysicalInterface
				
				np.IfName = phys
				np.VLAN   = vlan
				*physical = append(*physical, np)

				if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoInterfaces(): done, physical; ifname = '%s', vlan = '%s'\n", np.IfName, np.VLAN) }
			}
			
			i := strings.Split(v, ":")

			name	= i[0]
			phys	= ""
			up		= false
			vlan	= ""
			ip		= ""
			
			if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): name = %s\n", name) }

			d := strings.Split(i[1], " ")
			
			for idx, vv := range d {
				//if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): vv = %s\n", vv) }
				
				if strings.Contains(vv, "flags=") && strings.Contains(vv, "UP") {
					up = true
					
					//if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): up = %q\n", up) }
				} else if strings.Contains(vv, "vlan-id") {
					vlan = strings.TrimSpace(d[idx + 1])
					
					//if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): VLAN = %s\n", vlan) }
				}
			}
		} else {																// contiuation of interface data
			d := strings.Split(strings.TrimSpace(v), " ")
			n := len(d)
			
			for idx, vv := range d {
				if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): idx = %d, n = %d, vv = %s\n", idx, n, vv) }
				if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): d = %q\n", d) }
				
				var err error
				
				if strings.Contains(vv, "inet") && n >= 5 && ip == "" {
					// let's find the ip-address/mask
					_, _, err = net.ParseCIDR(d[idx + 3])
					if err != nil {
						_, _, err = net.ParseCIDR(d[idx + 4])
						if err != nil {
							if n >= 6 {
								_, _, err = net.ParseCIDR(d[idx + 5])
								if err != nil {
									ip = ""
								} else {
									ip = d[idx + 5]
								}
							} else {
								ip = ""
							}
						} else {
							ip = d[idx + 4]
						}
					} else {
						ip = d[idx + 3]
					}
					
					if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): inet (1); '%s'\n", ip) }
				} else if strings.Contains(vv, "inet") && n == 4 && ip == "" {
					_, _, err = net.ParseCIDR(d[idx + 1])
					if err != nil {
						ip = ""
					} else {
						ip = d[idx + 1]
					}

					if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): inet (2); '%s'\n", ip) }
				} else if strings.Contains(vv, "phys") && n >= 2 {
					phys = strings.TrimSpace(d[idx + 1])
					//if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoInterfaces(): phys; '%s'\n", d[idx + 1]) }
				}
			}
		}
	}
	
	return nil
}

//
//
func (sshAction *SshAction) ipsoRoutes(result string, routes *Routes) (err error) {
	lines := strings.Split(result, "\n")
	
	// go thru each line
	for _, v := range lines {
		f := strings.Fields(strings.TrimSpace(v))
		n := len(f)
		
		if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoRoutes(): n = %d, d = %q\n", n, f) }
		
		if n == 6 {
			if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoRoutes(): '%s' -> '%s'\n", f[0], f[1]) }
			
			a  := strings.Split(f[0], "/")
		
			if len(a) == 1 {
				if f[0] != "default" {
					f[0] = f[0] + "/32"
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoRoutes(): (host-route) '%s' -> '%s'\n", f[0], f[1]) }
				} else {
					f[0] = "0.0.0.0/0"
					if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoRoutes(): (default) '%s' -> '%s'\n", f[0], f[1]) }
				}
			} else {
				ii  := strings.Split(a[0], ".")
				iin := len(ii)

    			if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoRoutes(): iin = %d, ii = %q\n", iin, ii) }
				
				if iin == 3 {
					f[0] = ii[0] + "." + ii[1] + "." + ii[2] + ".0" + "/" + a[1]
				} else if iin == 2 {
					f[0] = ii[0] + "." + ii[1] + ".0.0" + "/" + a[1]
				} else if iin == 1 {
					f[0] = ii[0] + ".0.0.0" + "/" + a[1]
				}

    			if sshAction.verbose >= 1 { fmt.Printf("SshAction::ipsoRoutes(): f[0] = %s\n", f[0]) }
			}
			
			var n NetworkRoute
			n.Net     = f[0]
			n.Gateway = f[1]
			n.Dev     = f[5]
			
			_, ipnet, err := net.ParseCIDR(f[0])
			if err != nil {
				fmt.Printf("SshAction::ipsoRoutes(): %q -- %d\n", f, n)
				fmt.Printf("SshAction::ipsoRoutes(): '%s' -> '%s'\n", f[0], f[1])
    			fmt.Printf("SshAction::ipsoRoutes(): invalid network: %s\n", err.Error())
				
				//return false
			} else {
				n.IPNet = *ipnet
				
				*routes = append(*routes, n)
				
				if sshAction.verbose > 0 { fmt.Printf("SshAction::ipsoRoutes(): %s / %s -> %s\n", n.IPNet.IP.String(), n.IPNet.Mask.String(), n.Gateway) }
			}
		}
	}
	
	return nil
}
	
/******************************************************************************************************************
* helper functions
*
*/

//
//
func (slice LogicalInterfaces) Len() int {
    return len(slice)
}

//
//
func (slice LogicalInterfaces) Less(i, j int) bool {
    return slice[i].IfName < slice[j].IfName
}

//
//
func (slice LogicalInterfaces) Swap(i, j int) {
    slice[i], slice[j] = slice[j], slice[i]
}

//
//
func (slice PhysicalInterfaces) Len() int {
    return len(slice)
}

//
//
func (slice PhysicalInterfaces) Less(i, j int) bool {
    return slice[i].IfName + slice[i].VLAN < slice[j].IfName + slice[j].VLAN
}

//
//
func (slice PhysicalInterfaces) Swap(i, j int) {
    slice[i], slice[j] = slice[j], slice[i]
}

//
//
func (slice Routes) Len() int {
    return len(slice)
}

//
//
func (slice Routes) Less(i, j int) bool {
	addr_i := uint32(slice[i].IPNet.IP[0]) << 24 | uint32(slice[i].IPNet.IP[1]) << 16 | uint32(slice[i].IPNet.IP[2]) << 8 | uint32(slice[i].IPNet.IP[3])
	addr_j := uint32(slice[j].IPNet.IP[0]) << 24 | uint32(slice[j].IPNet.IP[1]) << 16 | uint32(slice[j].IPNet.IP[2]) << 8 | uint32(slice[j].IPNet.IP[3])

	return addr_i < addr_j
}

//
//
func (slice Routes) Swap(i, j int) {
    slice[i], slice[j] = slice[j], slice[i]
}

func ipNetToUint32(ip net.IP) (n uint32) {
	return uint32(ip[0]) << 24 | uint32(ip[1]) << 16 | uint32(ip[2]) << 8 | uint32(ip[3])
}