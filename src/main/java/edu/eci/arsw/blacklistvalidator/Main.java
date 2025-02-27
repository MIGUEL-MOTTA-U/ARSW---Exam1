/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import java.util.List;

/**
 *
 * @author hcadavid
 */
public class Main {
    
    public static void main(String a[]){
        HostBlackListsValidator hblv=new HostBlackListsValidator();
        List<Integer> blackListOcurrences=hblv.checkHost(10, "212.24.24.55"); // "202.24.34.55"); // "200.24.34.55" --> Instant
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences);

        List<Integer> blackListOcurrences2=hblv.checkHost(100, "202.24.34.55"); //  "200.24.34.55" --> Instant
        System.out.println("The host was found in the following blacklists:"+blackListOcurrences2);
        
    }
    
}
