
# Scoring API
Simple example of scoring API with  field in django forms style:)
It takes `POST` request with following params:
```
account ‐ optional string, could be empty
login - mandatory string, could be empty
method - mandatory string, could be empty
token - mandatory string, could be empty
arguments - mandatory dict, could be empty
    |
    |-> phone - optional string, could be empty. Have to have 11 char length and starts from 7
    |-> email - optional string, could be empty. Should have `@` symbol
    |-> first_name - optional string, could be empty
    |-> last_name - optional string, could be empty
    |-> birthday - optional string or datetime object in format DD.MM.YYYY, could be empty
    |-> gender - optional integer with values 0, 1, 2, could be empty
    |-> client_ids - mandatory list or tuple of integers, could not be empty
    |-> date - optional string or datetime object in format DD.MM.YYYY, could be empty
```
## Simple run
It's written and tested on Python *2.7.12*
```
$ git clone https://github.com/ligain/03_oop.git
$ cd 03_oop
$ python api.py
```
If you see something like:
```
[2018.06.26 12:52:36] I Starting server at 8080
```
so API works and you can send request:
`curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "admin", "method": "clients_interests", "token": "ca6e15ee5029bc7fc2499271e99857f947d3dd322c3041fc03b5d86cc218cd50b637befd503345c4d0e8b48e57fc1a3db402777be370c7eeb18803f16f0b0ad1" "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}}' http://127.0.0.1:8080/method/`
or
`curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f",
"method": "online_score", "token":
"55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af3
"arguments": {"phone": "79175002040", "email": "john@example.com", "first_name": "John",
"last_name": "Doe", "birthday": "01.01.1990", "gender": 1}}' http://127.0.0.1:8080/method`

*Note that token field is an auto generated field based on current time!*

## Tests
```
$ cd 03_oop
$ python test.py
```

### Project Goals

The code is written for educational purposes.