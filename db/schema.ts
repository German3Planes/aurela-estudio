import {sqliteTable,text,integer} from "drizzle-orm/sqlite-core";
export const clients=sqliteTable("clients",{dni:text("dni").primaryKey(),salt:text("salt").notNull(),hash:text("hash").notNull()});
export const sessions=sqliteTable("sessions",{token:text("token").primaryKey(),dni:text("dni").notNull(),expires:integer("expires").notNull()});
export const albums=sqliteTable("albums",{id:text("id").primaryKey(),dni:text("dni").notNull(),title:text("title").notNull(),expires:integer("expires").notNull()});
export const media=sqliteTable("media",{id:text("id").primaryKey(),album:text("album").notNull(),name:text("name").notNull(),type:text("type").notNull()});
export const attempts=sqliteTable("attempts",{id:text("id").primaryKey(),count:integer("count").notNull(),until:integer("until").notNull()});
