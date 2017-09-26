/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"os"
	"fmt"
	"bufio"
	"github.com/vpaprots/bccsp/ep11status/utils"
)

const EP11_DEVICE_CONFIGURATION = "./devices.conf"

func getClientDeviceList(filename string)([]int, int, error) {
	var list []int
	var length = 0
	var id, dom int

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		apqn := scanner.Text()
		fmt.Sscan(apqn, &id, &dom)
		list = append(list, id)
		list = append(list, dom)
		length = length + 2
	}
	header := [2]int{00, length}
	list = append(header[:], list[0:]...)
	return list, length + 2, err
}

func main() {
	ep11_domain_info := make([]utils.EP11_domain_info_t, utils.MAX_DOMAINS);
	var ep11_domain_info_len = utils.MAX_DOMAINS

	/*** get device list defined by the guest ***/
	devs, len, err := getClientDeviceList(EP11_DEVICE_CONFIGURATION)
	if (err != nil) {
		fmt.Printf("Could not get device list!\n", devs)
	}
	fmt.Printf("Desired devices [%v]: %v\n", (len-2)/2, devs)

	/*** get device list supported by the host ***/
	rc := utils.GetEP11status(&ep11_domain_info[0], &ep11_domain_info_len)
	if rc != 0 {
		fmt.Errorf("GetEP11status returned 0x%x\n", rc)
	}

	/*** DEBUG INFO **/
	var i int
	for i = 0; i < ep11_domain_info_len; {
		fmt.Printf("ID: %02x, Dom: %02x, WK[curr]: %x, state: %x, WK[next]: %x, state: %x\n",
			    ep11_domain_info[i].Id, ep11_domain_info[i].Dom,
			    ep11_domain_info[i].Hash_curr, ep11_domain_info[i].State_curr,
			    ep11_domain_info[i].Hash_next, ep11_domain_info[i].State_next)
		i++
	}
	/*****************/

	/*** check if all devices desired by the guest are configured with the same WK ***/
	devs, len = utils.ValidateDevices(devs, len, ep11_domain_info, ep11_domain_info_len)
	fmt.Printf("Approved device list contain %v devices: %v\n", (len-2)/2, devs)

	/* This 'devs' list can be passed to the ep11 m_<functions> */
}
