import os
import random
import subprocess
import time

mqtt_broker="192.168.100.100"
mqtt_port="1883"
mqtt_topic = "/auth"

config_dir="/home/raspi/mqtt_tasks/mqtt_industrial/protocol/config/"
ascon_dir = "/home/raspi/mqtt_tasks/mqtt_industrial/protocol/ascon-c/encrypt/"
hash_dir = "/home/raspi/mqtt_tasks/mqtt_industrial/protocol/ascon-c/hash/"

# read ctr and update it
with open(f"{config_dir}ctr_bro", "r") as f:
        ctr=int(f.read())

print(f"[+] CTRi (10 Bytes): {ctr}")

# read Nid and Bid and combine them to pass as nonce
with open(f"{config_dir}nid", "r") as f:
        nid=f.readline().replace('\n','')

with open(f"{config_dir}bid","r") as f:
        bid=f.read().replace('\n','')
nid_bid=f"{nid}{bid}"
print(f"[+] Nid||Bid (16 Bytes): {nid_bid}")

# read key
with open(f"{config_dir}k_bro","r") as f:
        k=f.read().replace('\n','')
print(f"[+] Initial Key (16 Bytes): {k}")

# mqtt connection: receiving M1
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
	m1_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m1=m1_temp.stdout.decode("utf-8").replace("\n","")
	print(f"\033[92m[+] M1={{Ci, Ti, CTRi, NIDi||BIDj}} has been received : {{{m1}}}\033[0m")
except:
	exit()
m1_=m1.split(",")
cipher=m1_[0]
tag = m1_[1]
received_ctr = m1_[2]
nid_bid=m1_[3]

# check CTRs
if int(received_ctr) < ctr:
	print("[-] CTRi is not correct!")
	exit()

# authenticate: decrypte
try:
	decrypt_m1 = subprocess.run(
	        [
	                f'{ascon_dir}ascon',
	                'dec',
	                cipher, # payload
	                str(len(cipher)), # payload's length
	                k, # key
	                nid_bid, # nonce
	                str(received_ctr), # additional data
			tag, # received tag
			str(len(tag)) # tag's size
	        ],
	        stdout=subprocess.PIPE
	)
	decrypted_m1=decrypt_m1.stdout.decode('utf-8').replace("\n","")
except Exception as e:
	exit()
print(f"[+] Decrypted M1: {decrypted_m1}")

rn = decrypted_m1[:10]
received_topic = decrypted_m1[10:-2]
received_sub_pub_revoc = decrypted_m1[-2:]

# save M1 in DB
with open(f"{config_dir}DB", "a") as f:
	f.write(f"{decrypted_m1}\n")

# update CTR
with open(f"{config_dir}ctr_bro", "w") as f:
	f.write(str(received_ctr))

# generate random number
rb=random.randint(1_000_000_000,9_999_999_999)

# encrypt M2
try:
	payload = f"{rb}{rn}{received_topic}{received_sub_pub_revoc}"
	print(f"[+] Rb||Rn||Topi||(Sub|Pub|Revoc): {payload}")
	encrypted_temp=subprocess.run(
	        [
	                f'{ascon_dir}ascon',
	                'enc',
	                payload, # payload
	                str(len(payload)), # payload's length
	                k, # key
	                nid_bid, # nonce
	                str(received_ctr) # additional data
	        ],
	        stdout=subprocess.PIPE
	)

	aead=encrypted_temp.stdout.decode('utf-8').split("\n")[:-1]
except:
	exit()
cipher = aead[1][7:]
tag = aead[0][7:]
m2=f"{cipher},{tag}"

print(f"\033[92m[+] Sending M2={{Cj, Tj}} : {{{m2}}}\033[0m")

# mqtt connection: sending m2
os.system(f"mosquitto_pub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -m '{m2}' > /dev/null")

# generating H(CTRi || Rn || Rb)
try:
	payload = f"{received_ctr}{rn}{rb}"
	hashed_temp=subprocess.run(
	        [
	                f'{hash_dir}hash',
	                payload, # payload
	                str(len(payload)), # payload's length
	        ],
	        stdout=subprocess.PIPE
	)

	hash=hashed_temp.stdout.decode('utf-8').replace("\n","")
except:
	exit()

print(f"\033[1m[+] Done. SK= {hash}\033[0m")
