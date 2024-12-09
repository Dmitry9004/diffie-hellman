// версия 0.0.1
// содержит реализацию протокла Диффи-Хеллмана
// алгоритмы проверки числа на простоту выделены в класс (наследующие) PrimeChecker
// алгоритмы генерации чисел выделены в клас (наследующие) Generator
// содержит разделение на клиента и сервер
// не поддерживает потоковую обработку

// закомментированный код находится в тестовом режиме (возможны модификации и удаление)
#include <cmath>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string_view>

// #define DEFAULT_PORT_SERV 8669
#define DEFAULT_PORT_SERV 8661
#define NUM_BIT_GENERATED 6
#define DEFAULT_HOST "127.0.0.1"
#define COUNT_LISTEN 1
#define MAX_BITS_RAND 16
#define MAX_MSG_LEN 200

using namespace std;

//сообщения, которое будет шифроваться секретным ключом
struct Message {
	public:
		void setText(string text) { this->text = text; }
		string getText() { return this->text; }
	
	private:
		string text;
};


//абстрактный класс генераторов чисел
class Generator {
	public:
		Generator() {}
		// const - не меняет поля класса
		virtual unsigned long generate() const = 0;
	protected:
		int n;
};


//наследующий класс генератора, позволяет сгенерировать число определнной раздяности 
class RandomExp2PrimeGenerator : public Generator {
	public:
		RandomExp2PrimeGenerator() {}
		unsigned long generate() const {
			const int bits = NUM_BIT_GENERATED;
			bitset<bits> a;

			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<> dis(0,1);

			for (int i = 0; i < bits; i++) { a[i] = dis(gen); }

			a[0] = 1;
			a[bits - 1] = 1;

			return a.to_ullong();
		}
};


//наследующий клаасс генератор, позволяет сгенерировать примитивные корни числа
class PrimitiveRootGenerator : public Generator {
	public:
		PrimitiveRootGenerator(unsigned long c_p): p(c_p) {}
		unsigned long generate() const {

			//функция эйлера
			for (unsigned long i = p/3; i < p; i++) {
				if (__gcd(i, this->p) == 1) { return i; }
			}

			return -1;
		}
	private:
		unsigned long p;
};

//абстрактный класс для разделения реализаций проверяющих число на простоту методов (проверка на простоту)
class PrimeChecker {
	public:
		PrimeChecker(Generator* c_generator) : generator(c_generator) {}
	
	protected:
		Generator* generator;
};

//наследюущий класс провверки проверки на протсоту, реализует метод Рабина-Миллера
class RabinMillerPrimeChecker : public PrimeChecker {
	public:	
		RabinMillerPrimeChecker(Generator* c_generator) : PrimeChecker(c_generator) {}
		
		bool isPrime(int cand) {
		 	int maxDivByTwo = 0;
		 	int evenComponent = cand-1;

		 	while(evenComponent % 2 == 0) {
		 		evenComponent >>= 1;
		 		maxDivByTwo += 1;
		 	}

		 	int numOfRabinTrials = 15;
		 	for (int i = 0; i < numOfRabinTrials; i++) {
		 		int round_tester = rand() * (cand - 2) + 2;

		 		if (trialComposite(round_tester, evenComponent, cand, maxDivByTwo)) {
		 			return false;
		 		}
		 	}
		 	return true;
		 }

	private:
		long expmod(int base, int exp, int mod) {
			if (exp <= 0) {
				return 1;
			}

			if (exp % 2 == 0) {
				return (long)pow(expmod(base, (exp/2), mod), 2) % mod;
			} else {
				return (base * expmod(base, (exp - 1), mod)) % mod;
			}
		}

		bool trialComposite(int round_tester, int evenComponent, int cand, int maxDivByTwo) {
			if (expmod(round_tester, evenComponent, cand) == 1) {
				return false;
			}
			try {
				for(int i = 0; i < maxDivByTwo; i++) {
					if (expmod(round_tester, (1 << i) * evenComponent, cand) == cand - 1) {
						return false; 
					}
				}

				return true;
			}catch(const char* error_mess) {
				std::cout << error_mess << std::endl; 
			}
		}
};

//налследующий класс проверки числа на протсоту, реализует простую проверку на простоту делением первых простых чисел 
class SimplePrimeChecker : public PrimeChecker {
	public:
		SimplePrimeChecker(Generator* c_generator) : PrimeChecker(c_generator) {}
		unsigned long checkAndGetPrime() {
			// or vector ....
			vector<int> simple_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443};

			while(true) {
				unsigned long prime_candidate = generator->generate();

				bool is_prime_f = true;
				for (int i = 0; i < simple_primes.size(); i++) {
					if (prime_candidate % simple_primes[i] == 0 && simple_primes[i]*simple_primes[i] <= prime_candidate) {
						is_prime_f = false;
						break;
					}
				}

				if (is_prime_f) { return prime_candidate; }
			}
		}
};

//класс канала, позволяет участниками информационного обмена, получать и отправлять сообщения
//реализцется на методе передачй сокетами
class Channel {
	public:
		Channel(int conn) { this->conn = conn; }

		void sendNum(unsigned long long int num) {
			char* data = (char*)&num;
			int size = sizeof(num);
			int res = 0;
			int sent = 0;

			while(size > 0) {
				res = send(this->conn, data+sent, size, 0);
				if (res > 0) {
					size -= res;
					sent += res;
				} else if (res < 0) { }
			}

		};

		unsigned long long int getNum() {
			long num = 0;
			char* recv_buff = (char*)&num;
			int size = sizeof(unsigned long long int);
			int recvi = 0;
			int res = 0;

			while(size > 0) {
				res = recv(this->conn, recv_buff+recvi, size,0);
				if (res > 0) {
					size -= res;
					recvi += res;
				}
			}

			return num;
		};

		vector<unsigned long long int> get_vals() {
			long size = 3;
			vector<unsigned long long int> vals;
			vals.resize(size);
			recv(this->conn, &(*vals.begin()), size * sizeof(unsigned long long int), 0);

			return vals;
		};
		void sendVals(vector<unsigned long long int> vals) {
			send(this->conn, &(*vals.begin()), 3*sizeof(unsigned long long int), 0);
		};

		void sendMessage(Message* message) {
			string text = message->getText();

			int len = htonl(text.size());
			send(this->conn, &len, sizeof(int), 0);
			send(this->conn, text.c_str(), text.size(), 0);
		};

		void getMessage(Message* message) {
			vector<char> buff(MAX_MSG_LEN);
			string res;
			int count_bytes = 0;
			do {
				count_bytes = recv(this->conn, &buff[0], buff.size(), 0);
				if (count_bytes == -1) { }
				else {
					res.append(buff.cbegin(), buff.cend());
				}

			} while(count_bytes == MAX_MSG_LEN);

			message->setText(res);
		};
	protected:
		int conn;
};

//абстрактный класс для разделения участника на сервер и клиент
class TypeSide {
	public:
		TypeSide(int port, char* ip) {}
		void virtual setConfigureConnection() = 0;
		// Channel* virutal setConnection() = 0;
	protected:
		int port;
		char* ip;
};

//утилита для возведения числа в степень
unsigned long long int pow_unsl(unsigned long x, unsigned int y)
{
    unsigned long long int res = 1;
    while (y > 0)
    {
        if (y & 1)
            res *= x;
        y >>= 1;
        x *= x;
    }

    return res;
}
// библиотечный код, был взят для хеширования строк 
string hash_str(string_view dec_key, string_view msg) {
	array<unsigned char, EVP_MAX_MD_SIZE> hash;
	unsigned int hashLen;

	HMAC(
		EVP_sha256(),
		dec_key.data(),
		static_cast<int>(dec_key.size()),
		reinterpret_cast<unsigned char const*>(msg.data()),
		static_cast<int>(msg.size()),
		hash.data(),
		&hashLen
	);

	return string{reinterpret_cast<char const*>(hash.data()), hashLen};
}


//наследующий класс стороны клиента, представляет сервер
class ServerSide: public TypeSide {
	public:
		ServerSide(int port = DEFAULT_PORT_SERV, char* ip = DEFAULT_HOST) :TypeSide(port, ip) {
			this->port = port;
			this->ip = ip;
		}

		void setConfigureConnection() {
			int descrp; 
			struct sockaddr_in addr; 

			// (IPv4, tcp)
			descrp = socket(AF_INET, SOCK_STREAM, 0); 
			if (descrp <= 0) {
				cout << "ERROR CREATE SOCKET!" << endl;
				exit(1);
			}

			// use my ip addr
			if (this->ip == DEFAULT_HOST) { addr.sin_addr.s_addr = INADDR_ANY; }
			else { inet_pton(AF_INET, this->ip, &addr.sin_addr.s_addr); }

			addr.sin_family = AF_INET; 	
			addr.sin_port = htons(this->port);  

		    // связать дискриптор и сокет с которого будет происходить соединение
			if (bind(descrp, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
				cout << "ERRPR BIND DESCRIPTOR" << endl;
				exit(2);
			} 	
			
			// прослушивать дискриптор, n (1) соединений макс. (CONST)
			if (listen(descrp, COUNT_LISTEN) == -1) {
				cout << "ERROR LISTEN SOCKET" << endl;
				exit(3);
			} 

			// идентификатор соединения
			int conn = accept(descrp, NULL, NULL); 

			vector<long> candidates = {};

			unique_ptr<Generator> generator(new RandomExp2PrimeGenerator());	
			unique_ptr<SimplePrimeChecker> simple_prime_generator(new SimplePrimeChecker(generator.get()));
			unique_ptr<RabinMillerPrimeChecker> r_m_checker(new RabinMillerPrimeChecker(generator.get()));

			while(candidates.size() < 2) {
				long cand = simple_prime_generator->checkAndGetPrime(); 
				if (r_m_checker->isPrime(cand)) {
					candidates.push_back(cand);
				}
			}

			long p = candidates[0];

			unique_ptr<PrimitiveRootGenerator> primitive_root_generator(new PrimitiveRootGenerator(p));
			long g = primitive_root_generator->generate();

			// рандомизация получениф чиел, std::mt19937...			
			short A = rand() % (MAX_BITS_RAND - 1 + 1)+ 1;

			unsigned long long int y_a = pow_unsl(g, A) % p;

			unique_ptr<Channel> ch(new Channel(conn));				
			vector<unsigned long long int> vals{ p, g, y_a };
			ch->sendVals(vals);

			unsigned long long int y_b = ch->getNum();

			unsigned long long int d = pow_unsl(y_b, A);
			
			unsigned long long int secret_key = d % p; 

			hash<char> hash_string;

			// НАЧАЛО БЛОКА ПЕРЕДАЧИ СООБЩЕНИЙ С ПОМОЩЬЮ ШИФРОВАНИЯ СИММЕТРИЧНЫМ КЛЮЧОМ
			// const string dec_key = to_string(secret_key);
			// while(1) {
			// 	unique_ptr<Message> recv_msq(new Message());
			// 	ch->getMessage(recv_msq.get());
			// 	string res = hash_str(string_view(dec_key), string_view(recv_msq->getText()));

			// 	std::cout << "Message by client:" << std::endl;
			// 	std::cout << res << std::endl;

			// 	std::cout << "Enter message:" << std::endl;
			// 	char message[MAX_MSG_LEN];
			// 	std::cin.getline(message, MAX_MSG_LEN);

			// 	string decoded_msq = hash_str(string_view(dec_key), string_view(message));
			// 	unique_ptr<Message> message_data(new Message());
			// 	message_data->setText(decoded_msq);

			// 	ch->sendMessage(message_data.get());	
			// }
	}
};



//наследующий класс стороны клиента, представляет клиент
class ClientSide: public TypeSide {
	public:
		ClientSide(int port = DEFAULT_PORT_SERV, char* ip = DEFAULT_HOST) : TypeSide(port, ip) {
			this->port = port;
			this->ip = ip;
		}

		void setConfigureConnection() {
			int descrp;
			sockaddr_in	addr;

			descrp = socket(AF_INET, SOCK_STREAM, 0);
			if (descrp < 0) {
				cout << "ERROR CREATE CLIENT SOCKET";
				exit(1);
			}

			addr.sin_family	= AF_INET;
			addr.sin_port = htons(this->port);
			addr.sin_addr.s_addr = inet_addr(this->ip);

			if ( connect(descrp, (sockaddr*)&addr,sizeof(addr)) < 0) {
				cout << "ERROR CONNECT TO ADDRESS";
				exit(3);
			}
			unique_ptr<Channel> ch(new Channel(descrp));
			vector<unsigned long long int> vals = ch->get_vals();

			long p = vals[0];
			long g = vals[1];
			unsigned long long int y_a = vals[2];

			short B = rand() % (16 - 5 + 1)+ 5;

			unsigned long long int y_b = pow_unsl(g, B) % p;

			ch->sendNum(y_b);

			unsigned long long int d = pow_unsl(y_a, B);

			const unsigned long long int secret_key = d % p; 

			// НАЧАЛО БЛОКА ПЕРЕДАЧИ СООБЩЕНИЙ С ПОМОЩЬЮ ШИФРОВАНИЯ СИММЕТРИЧНЫМ КЛЮЧОМ
			// const string dec_key = to_string(secret_key);
			// while(1) {
			// 	std::cout << "Enter message:" << std::endl;
			// 	char message[MAX_MSG_LEN];
			// 	std::cin.getline(message, MAX_MSG_LEN);
				
			// 	string decoded_msq = hash_str(string_view(dec_key), string_view(message));
			// 	unique_ptr<Message> message_data(new Message());
				
			// 	message_data->setText(decoded_msq);
			// 	ch->sendMessage(message_data.get());	

			// 	unique_ptr<Message> recv_msq(new Message());
			// 	ch->getMessage(recv_msq.get());
			// 	string res = hash_str(string_view(dec_key), string_view(recv_msq->getText()));
				
			// 	std::cout << "Message by server:" << std::endl;
			// 	std::cout << res << std::endl;
			// }
		}
};

int main() {
	// // int i;
	// // cout << "Enter type connection from you (1 - server, 0 - client):";		
	// // cin >> i;
	// // while (cin.fail() || i != 1 && i != 0) {
	// // 	cout << "Not valid, please enter type connection (1 - server, 0 - client):";		
	// // 	cin.clear();
	// // 	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	// // 	cin >> i;
	// // }

	// ClientSide* cl = new ClientSide();
	// cl->setConfigureConnection();

	ServerSide* cl = new ServerSide();
	cl->setConfigureConnection();
}
