package com.github.luben.process;

public class Process {

    static {
        System.out.println("Loading library");
        try {
            System.loadLibrary("process");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load.\n" + e);
        }
    }

    /**
     * Fork new process.
     * @return  The pid or 0
     */
    public static native int fork();

    public static native int waitpid(int pid, int options);

    public static native int execv(String path, String[] args);

    public static native int posix_spawn(String path, String[] args);

    public static native int prctl(int option, long arg2, long arg3, long arg4, long arg5);

    public static native String[] getgrouplist(String user);

    public static native boolean login(String user, String password);
}
