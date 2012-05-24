CREATE TABLE addresses(
	hwmac TEXT, 
	address INT,
	first_seen DATETIME DEFAULT current_timestamp,
	last_seen DATETIME DEFAULT current_timestamp
);
