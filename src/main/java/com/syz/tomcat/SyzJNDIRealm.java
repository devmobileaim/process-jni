package com.syz.tomcat;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.github.luben.process.Process;

public class SyzJNDIRealm extends RealmBase {

    protected List<RoleMapping> mappings = new ArrayList<>();

    public void addRoleMapping(RoleMapping roleMapping) {
        mappings.add(roleMapping);
    }

    public RoleMapping[] findRoleMappings() {
        return (RoleMapping[]) mappings.toArray();
    }

    protected String mapping;

    public void setMapping(String mapping) {
        Pattern pattern = Pattern.compile("([a-zA-Z][a-zA-Z]*)\\='([^'][^']*)'");
        Matcher m = pattern.matcher(mapping);
        while (m.find()) {
            RoleMapping roleMapping = new RoleMapping();
            if (!m.group(1).equals("adGroup")) {
                log.error("Wrong mapping format");
                return;
            }
            roleMapping.setAdGroup(m.group(2));
            log.info("Add mapping adGroup=" + m.group(2));
            if (!m.find() || !m.group(1).equals("roles")) {
                log.error("Wrong mapping format");
                return;
            }
            for (String role : m.group(2).split(",")) {
                Role roleObj = new Role();
                roleObj.setName(role);
                roleMapping.addRole(roleObj);
            }
            addRoleMapping(roleMapping);
            log.info(" roles= " + m.group(2));
        }
        this.mapping = mapping;
    }

    public String getMapping() {
        return this.mapping;
    }

    protected void mapRoles(List<String> roles) {
        log.info(roles.size() + " roles retrieved");
        List<String> newRoles = new ArrayList<>();
        for (String role : roles) {
            log.info("Roles = " + role);
            for (RoleMapping mapping : mappings) {
                if (role.equalsIgnoreCase(mapping.adGroup)) {
                    for (Role newRole : mapping.getRoles()) {
                        newRoles.add(newRole.getName());
                        log.info("Add new role " + newRole.getName());
                    }
                }
            }
        }
        roles.addAll(newRoles);
    }

    private static final Log log = LogFactory.getLog(SyzJNDIRealm.class);
    private static final String NAME = "SyzJNDIRealm";

    @Override
    protected String getName() {
        return NAME;
    }

    Map<String, String> passwords = new HashMap<>();

    @Override
    public Principal authenticate(String username, String credentials) {
        Principal principal = null;
        try {
            log.info("Authenticate user "+username);
            if  (Process.login(username, credentials)) {
                log.info("User Authenticated "+username);
                List<String> roles = new ArrayList<String>(Arrays.asList(Process.getgrouplist(username)));
                log.info("User has "+roles.size()+ " roles");
                mapRoles(roles);
                this.passwords.put(username, credentials);
                principal = new GenericPrincipal(username, credentials, roles);
            } else {
                log.error("Bad credentials");
            }
        } catch (Throwable t) {
            // handle errors
            log.error("Failed to authenticate", t);
            principal = null;
        }

        return principal;
    }

	@Override
	protected String getPassword(String username) {
        log.info("GetPassword "+username);
		return this.passwords.get(username);
	}

	@Override
	protected Principal getPrincipal(String username) {
        log.info("GetPrincipal "+username);
        log.info("User Authenticated "+username);
        List<String> roles = new ArrayList<String>(Arrays.asList(Process.getgrouplist(username)));
        log.info("User has "+roles.size()+ " roles");
        mapRoles(roles);
        return new GenericPrincipal(username, null, roles);
	}

}