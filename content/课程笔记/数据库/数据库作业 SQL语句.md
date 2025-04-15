---
draft: true
---
### 7.11

##### ROOM表：

```SQL
CREATE TABLE Room(
	roomNo INT NOT NULL CHECK (roomNo>=1 AND roomNo<=100),
	roomType VARCHAR(6) NOT NULL CHECK (roomType in ('Single','Double','Famliy')),
	price INT NOT NULL CHECK (price>=10 AND price<=100),
	PRIMARY KEY (roomNo)
)
```

##### Booking表：

```SQL
CREATE TABLE Booking(
	roomNo INT NOT NULL CHECK (roomNo>=1 AND roomNo<=100),
	guestNo INT NOT NULL,
	dateFrom DATE NOT NULL CHECK (dateFrom>=CURRENT_DATE),
	dateTo DATE NOT NULL CHECK (dateTO>=CURRENT_DATE),
	PRIMARY KEY (roomNo, guestNo, dateFrom),

)

```

##### Guest表：

```SQL
CREATE TABLE Guest(
	
	
)
```