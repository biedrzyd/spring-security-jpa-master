package io.javabrains.springsecurityjpa.models;

import javax.persistence.*;

@Entity
@Table(name = "password")
public class Password {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column
    private Integer id;
    @Column
    private Integer userid;
    @Column
    private String site;
    @Column
    private String password;

    public String getDecryptpass() {
        return decryptpass;
    }

    public void setDecryptpass(String decryptpass) {
        this.decryptpass = decryptpass;
    }

    private String decryptpass;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Integer getUserid() {
        return userid;
    }

    public void setUserid(Integer userid) {
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



}
