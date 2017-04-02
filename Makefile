all:
	g++ -Wall -Wextra -g -o kry *.cpp -lboost_system -lgmpxx -lgmp -lcrypto
