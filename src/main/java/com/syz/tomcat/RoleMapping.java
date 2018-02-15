package com.syz.tomcat;

import java.util.ArrayList;
import java.util.List;

public class RoleMapping {
    protected List<Role> roles = new ArrayList<>();

    protected String adGroup;
    
    public void addRole(Role role) {
        this.roles.add(role);
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setAdGroup(String adGroup) {
        this.adGroup = adGroup;
    }

    public String getAdGroup() {
        return this.adGroup;
    }

}