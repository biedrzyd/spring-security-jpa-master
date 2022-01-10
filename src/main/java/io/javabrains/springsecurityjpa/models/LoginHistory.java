package io.javabrains.springsecurityjpa.models;

import javax.persistence.*;
import java.util.Date;
@Entity
@Table(name = "logins")
public class LoginHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    private int userid;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getUserid() {
        return userid;
    }

    public void setUserid(int userid) {
        this.userid = userid;
    }

    public Date getTime() {
        return time;
    }

    public void setTime(Date time) {
        this.time = time;
    }

    private Date time;

}
