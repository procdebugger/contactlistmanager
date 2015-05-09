drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  pw_hash text not null
);

drop table if exists follower;
create table follower (
  who_id integer,
  whom_id integer
);

drop table if exists message;
create table message (
  message_id integer primary key autoincrement,
  author_id integer not null,
  text text not null,
  pub_date integer
);

drop table if exists contact;
create table contact (
	contact_id integer primary key autoincrement,
	contact_name text not null,
	address text not null
);

drop table if exists usercontact;
create table usercontact (
	usercontact_id integer primary key autoincrement,
	contact_id integer,
	user_id integer
);