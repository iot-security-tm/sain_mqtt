import os
import subprocess
import random
import time

# timing
start=time.time()

# consts
mqtt_broker="192.168.100.100"
mqtt_port="1883"
mqtt_topic = "/auth"

config_dir="/home/raspi/mqtt_tasks/mqtt_industrial/protocol/config/"
ascon_dir = "/home/raspi/mqtt_tasks/mqtt_industrial/protocol/ascon-c/encrypt/"
hash_dir = "/home/raspi/mqtt_tasks/mqtt_industrial/protocol/ascon-c/hash/"

# read ctr and update it
with open(f"{config_dir}ctr_sub", "r") as f:
	ctr=int(f.read())
ctr+=1
print(f"[+] CTRi (10 Bytes): {ctr}")

# read Nid and Bid and combine them to pass as nonce
with open(f"{config_dir}nid", "r") as f:
	nid=f.readline().replace('\n','')

with open(f"{config_dir}bid","r") as f:
	bid=f.read().replace('\n','')

nid_bid=f"{nid}{bid}"

print(f"[+] Nid||Bid (16 Bytes): {nid_bid}")

# read key
with open(f"{config_dir}k_sub","r") as f:
	k=f.read().replace('\n','')
print(f"[+] Key (16 Bytes): {k}")

# generate payload (Rn || Topi || (Sub|Pub|Revoc))
rn=random.randint(1_000_000_000,9_999_999_999)
t = mqtt_topic # it can not be smaller than 5
sub_pub_revoc="01" # 01: Sub, 10: Pub,  00: Revoc

#encryption
payload = f"{rn}{t}{sub_pub_revoc}"
print(f"[+] Rn||Topi||(Sub|Pub|Revoc): {payload}")
try:
	encrypted_temp=subprocess.run(
		[
			f'{ascon_dir}ascon',
			'enc',
			payload, # payload
			str(len(payload)), # payload's length
			k, # key
			nid_bid, # nonce
			str(ctr) # additional data
		],
		stdout=subprocess.PIPE
	)
	aead=encrypted_temp.stdout.decode('utf-8')
	aead=aead.split("\n")[:-1]
	tag=aead[0][7:]
	cipher=aead[1][7:]
except:
	exit()
m1=f"{cipher},{tag},{ctr},{nid_bid}"
print(f"\033[92m[+] Sending M1={{Ci, Ti, CTRi, NIDi||BIDj}} : {{{m1}}}\033[0m")
#print(f"Len M1:{len(m1)}")

# mqtt connection: sending m1
os.system(f"mosquitto_pub -h {mqtt_broker} -p {mqtt_port} -t {t} -m '{m1}' > /dev/null")

# mqtt connection: receiving m2
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
	m2_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m2=m2_temp.stdout.decode("utf-8").replace("\n","")
	print(f"\033[92m[+] M2={{Ci, Ti}} has been received : {{{m2}}}\033[0m")
except:
	exit()
# decrypt M2
cipher = m2.split(",")[0]
tag = m2.split(",")[1]
try:
	decrypt_m2 = subprocess.run(
	        [
	                f'{ascon_dir}ascon',
	                'dec',
	                cipher, # payload
	                str(len(cipher)), # payload's length
	                k, # key
	                nid_bid, # nonce
	                str(ctr), # additional data
	                tag, # received tag
	                str(len(tag)) # tag's size
	        ],
	        stdout=subprocess.PIPE
	)
	decrypted_m2=decrypt_m2.stdout.decode('utf-8').replace("\n","")
except:
	exit()
print(f"[+] Decrypted M2: {decrypted_m2}")


# generating H(CTRi || Rn || Rb)
rb=decrypted_m2[:10]
payload = f"{ctr}{rn}{rb}"
hashed_temp=subprocess.run(
        [
                f'{hash_dir}hash',
                payload, # payload
                str(len(payload)), # payload's length
        ],
        stdout=subprocess.PIPE
)

hash=hashed_temp.stdout.decode('utf-8').replace("\n","")

print(f"\033[1m[+] Done. SK= {hash}\033[0m")

end=time.time()
elapsed_time=(end-start)*1000
print(f"---------------\nElapsed Time (millisec):{elapsed_time} ")
with open("timing","a") as f:
	f.write(str(elapsed_time)+"\n")
