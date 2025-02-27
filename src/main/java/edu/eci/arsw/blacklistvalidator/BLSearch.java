package edu.eci.arsw.blacklistvalidator;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

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
        this.searcher = searcher;
        this.sharedOcurrencesList = sharedOcurrencesList;
        this.currentPosition = start;
        this.checkedLists = checkedLists;
        this.endPosition = end;
        this.ipaddress = ipAddress;
        this.sharedCount = sharedCount;
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
