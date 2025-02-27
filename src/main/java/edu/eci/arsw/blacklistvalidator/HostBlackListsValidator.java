/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    public static final int BLACK_LIST_ALARM_COUNT=5;
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(int nThreads, String ipaddress){
        
        CopyOnWriteArrayList<Integer> blackListOcurrences = new CopyOnWriteArrayList<>();
        AtomicInteger ocurrencesCount=new AtomicInteger(0);
        AtomicInteger checkedLists = new AtomicInteger(0);
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        ArrayList<BLSearch> threads = new ArrayList<>(nThreads + 1);
        int size = skds.getRegisteredServersCount();
        int chunk = size / nThreads;
        int start = 0;
        int end;
        int remainder = size % nThreads;

        for (int i = 0; i < nThreads; i ++){

            end=start+chunk;

            BLSearch thread = new BLSearch(start, end - 1, ipaddress, ocurrencesCount, checkedLists,blackListOcurrences,skds);
            threads.add(thread);

            start=end;
        }
        if(remainder != 0) threads.add(new BLSearch(start, start + remainder, ipaddress, ocurrencesCount, checkedLists,blackListOcurrences, skds)); // System.out.println("Start: " + start +" End: " + (start + remainder))
        for(BLSearch b: threads){
            b.start();
        }
        for (BLSearch b: threads){
            try{
                b.join();
                if(ocurrencesCount.get()  >= HostBlackListsValidator.BLACK_LIST_ALARM_COUNT) break;


            } catch (InterruptedException e){
                Thread.currentThread().interrupt();
                System.out.println("Error while waiting threads");
            }
        }
        if (ocurrencesCount.get()>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }
        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedLists.get(), skds.getRegisteredServersCount()});
        
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    
}
