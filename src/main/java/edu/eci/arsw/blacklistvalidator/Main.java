/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import sun.awt.windows.ThemeReader;

import java.util.List;
import java.util.Scanner;

/**
 *
 * @author hcadavid
 */
public class Main {
    public static void main(String a[]){
        int NUMBER_THREADS = 10;
        HostBlackListsValidator hblv=new HostBlackListsValidator();
        // Check with a trustworthy IP
        long time1 = System.currentTimeMillis();
        List<Integer> blackListOcurrences=hblv.checkHost(NUMBER_THREADS, "212.24.24.55");
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences);
        long t2 = System.currentTimeMillis();
        System.out.println("Took : " + ((t2-time1) / 1000) + " seconds");


        // Check with a hard to find NOT trustworthy IP
        List<Integer> blackListOcurrences2=hblv.checkHost(NUMBER_THREADS, "202.24.34.55");
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences2);
        long t3 = System.currentTimeMillis();
        System.out.println("Took : " + ((t3-t2) / 1000) + " seconds");


        // Check with an easy to find NOT trustworthy IP
        List<Integer> blackListOcurrences3=hblv.checkHost(NUMBER_THREADS, "200.24.34.55");
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences3);
        long t4 = System.currentTimeMillis();
        System.out.println("Took : " + ((t4-t3) / 1000) + " seconds");
    }
    
}
