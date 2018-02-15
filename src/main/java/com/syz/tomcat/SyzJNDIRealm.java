package com.syz.tomcat;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
                System.err.println("Wrong mapping format");
                return;
            }
            roleMapping.setAdGroup(m.group(2));
            System.out.print("Add mapping adGroup=" + m.group(2));
            if (!m.find() || !m.group(1).equals("roles")) {
                System.err.println("Wrong mapping format");
                return;
            }
            for (String role : m.group(2).split(",")) {
                Role roleObj = new Role();
                roleObj.setName(role);
                roleMapping.addRole(roleObj);
            }
            addRoleMapping(roleMapping);
            System.out.println(" roles= " + m.group(2));
        }
        this.mapping = mapping;
    }

    public String getMapping() {
        return this.mapping;
    }

    protected void mapRoles(List<String> roles) {
        System.out.println(roles.size() + " roles retrieved");
        List<String> newRoles = new ArrayList<>();
        for (String role : roles) {
            System.out.println("Roles = " + role);
            for (RoleMapping mapping : mappings) {
                if (role.equalsIgnoreCase(mapping.adGroup)) {
                    for (Role newRole : mapping.getRoles()) {
                        newRoles.add(newRole.getName());
                        System.out.println("Add new role " + newRole.getName());
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

    @Override
    protected Principal getPrincipal(X509Certificate usercert) {
        log.info("getPrincipal X509");
        log.info("UserName : " + usercert.getSubjectDN().getName());

        String dn = usercert.getSubjectX500Principal().getName("RFC1779");
        String[] split = dn.split(",");
        String name = "";
        for (String x : split) {
            if (x.contains("CN=")) {
                name = x.replace("CN=", "").trim();
            }
        }
        List<String> roles = Arrays.asList(Process.getgrouplist(name));
        mapRoles(roles);

        Principal principal = new GenericPrincipal(name, null, roles);

        return principal;
    }

    @Override
    public Principal authenticate(String username, String credentials) {
        Principal principal = null;
        try {
            System.out.println("Authenticate user "+username);
            if  (Process.login(username, credentials)) {
                System.out.println("User Authenticated "+username);
                List<String> roles = Arrays.asList(Process.getgrouplist(username));
                System.out.println("User has "+roles.size()+ " roles");
                mapRoles(roles);
                principal = new GenericPrincipal(username, null, roles);
            }
        } catch (Throwable t) {
            // handle errors
            principal = null;
        }

        return principal;
    }

	@Override
	protected String getPassword(String username) {
		return null;
	}

	@Override
	protected Principal getPrincipal(String username) {
		return null;
	}

}