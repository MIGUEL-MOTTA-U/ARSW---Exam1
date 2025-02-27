package edu.eci.arsw.blacklistvalidator;


import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class HostBlackListsValidatorTest {
    private final HostBlackListsValidator hblv=new HostBlackListsValidator();

    @Test
    public void checkHost() {
        String IP = "200.24.34.55"; //
        List<Integer> occurrences=hblv.checkHost(10, IP);
        assertEquals(5, occurrences.size());
    }

    @Test
    public void checkNThreadsHost(){
        String IP = "200.24.34.55";
        for(int i = 1; i < 25; i++){
            List<Integer> occurrences=hblv.checkHost(i, IP);
            assertEquals(5, occurrences.size());
        }
    }

    @Test
    public void shouldNotFindHost(){
        String IP = "212.24.24.55";
        List<Integer> occurrences = hblv.checkHost(10, IP);
        assertEquals(0,occurrences.size());
    }
}