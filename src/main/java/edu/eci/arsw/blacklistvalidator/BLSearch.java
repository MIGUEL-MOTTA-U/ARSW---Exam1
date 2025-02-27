package edu.eci.arsw.blacklistvalidator;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

/**
 * This class provides the feature to search an IP in a given Interval
 * updating shared values like number of lists where the IP was found
 */
public class BLSearch extends Thread{
    private final AtomicInteger sharedCount;
    private final AtomicInteger checkedLists;
    private final CopyOnWriteArrayList<Integer> sharedOcurrencesList;
    private final int currentPosition;
    private final String ipaddress;
    private final int endPosition;
    private final HostBlacklistsDataSourceFacade searcher;

    final CopyOnWriteArrayList<String> searcList = new CopyOnWriteArrayList<>();

    public BLSearch(int start, int end, String ipAddress, AtomicInteger sharedCount, AtomicInteger checkedLists, CopyOnWriteArrayList<Integer> sharedOcurrencesList,HostBlacklistsDataSourceFacade searcher){
        if(end < start ) throw new RuntimeException("The start interval should be less than the end interval");
        this.searcher = searcher; // The searcher class
        this.sharedOcurrencesList = sharedOcurrencesList; // The list where the IP was found thread-safety
        this.currentPosition = start; // The current position to search in the Black list
        this.checkedLists = checkedLists; // The number of lists checked
        this.endPosition = end; // The final position to search in the Black list
        this.ipaddress = ipAddress; // The ip address to search in the Black list with the Searcher
        this.sharedCount = sharedCount; // The count of times that the IP was found in the Black List
    }

    @Override
    public void run(){
        for (int i = currentPosition; i <= endPosition; i++){
            if(sharedCount.get()  >= HostBlackListsValidator.BLACK_LIST_ALARM_COUNT) return;
            if (searcher.isInBlackListServer(i, ipaddress)){
                sharedOcurrencesList.add(i);
                sharedCount.incrementAndGet();
            }
            checkedLists.incrementAndGet();
        }
    }
}
