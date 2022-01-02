package io.javabrains.springsecurityjpa.models;

import javax.persistence.*;

@Entity
@Table(name = "userpasswords")
public class UserPasswords {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int iduserpasswords;
    private int userid;
    private String site;
    private String password;

    public int getUserid() {
        return userid;
    }

    public void setUserid(int userid) {
        this.userid = userid;
    }

    public String getSite() {
        return site;
    }

    public void setSite(String site) {
        this.site = site;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getId() {
        return iduserpasswords;
    }

    public void setId(int id) {
        this.iduserpasswords = id;
    }

}
