# Tenda M3 formSetRemoteVlanInfo Stack Overflow

## Description

The **formSetVlanInfo** handler in `/bin/httpd` calls **formSetRemoteVlanInfo** (under certain conditions) which is vulnerable to multiple stack overflows due to the complete absence of user input sanitization and bounds checking on parameters **ID**, **vlan**, and **port** which can lead to corruption of data on the stack, hijacking of control flow, and DoS. The attack can be performed remotely.

## Details

*   **Vendor**: Tenda

*   **Product**: Tenda M3

*   **Firmware Version**: V1.0.0.13(4903)_CN&EN

*   **Firmware Download**: https://www.tendacn.com/material/show/104888

*   **Component**: `/goform/setVlanInfo` (formSetVlanInfo handler -> formSetRemoteVlanInfo())

*   **Vulnerability Type**: Buffer Overflow (CWE-120) and Memory Corruption (CWE-119)

*   **CVE ID**: CVE-2025-15231

*   **Reported by**: Charbel


## PoC

The vulnerability is in the `memcpy()` calls with no bounds checking.

![Vulnerable Function](../resources/imgs/Tenda/setRemoteVlanInfoFn.png)

Let's examine `formSetVlanInfo` and see how `formSetRemoteVlanInfo` is called

![Parent Funciton](../resources/imgs/Tenda/SetRemoteVlanInfoParentFn.png)

As we can see, we need `FUN_00056668` to return 0, so let's examine that function

![Remote Detection Funciton](../resources/imgs/Tenda/setRemoteVlanInfoDetectRemoteFn.png)

So we need the following:  
✅ 1. Router configured with `ac.workmode=master` (can be set through `/bin/cfm`, or simply patch `/bin/httpd` if you're feeling lazy)  
✅ 2. HTTP request includes Cookie header  
✅ 3. Cookie contains devUid parameter  
✅ 4. devUid format: devUid=IP:PORT;  
✅ 5. IP must be valid dotted-quad format (xxx.xxx.xxx.xxx)  

Now we can send a POST request to the `/goform/setVlanInfo` endpoint to trigger the stack overflow in `formSetRemoteVlanInfo`

```
curl -X POST http://172.16.182.130/goform/setVlanInfo  -H "Cookie: devUid=172.16.182.130:80;" -d "ID=$(python3 -c 'print("A"*10000)')" -d "action=test" -d "vlan=1" -d "port=1"
```

![PoC](../resources/imgs/Tenda/SetRemoteVlanInfoPoC.png)
