package com.github.luben.process;

public class Test
{ 
	public static void main(String [] args) {
        String[] groups = Process.getgrouplist(args[0]);
        for (String group : groups) {
            System.out.println(group);
        }
        boolean logged = Process.login(args[0], args[1]);
        System.out.println(logged);
    }
}