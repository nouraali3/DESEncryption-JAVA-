/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package security;

import java.math.BigInteger;

/**
 *
 * @author user
 */
public class keyGen {
    public static void main(String[] args) {
        String[] roundKeys=new String[16];
        roundKeys=keyGeneration("00000000FFFFFFFF");
        
        for (String roundKey : roundKeys) 
            { System.out.println(roundKey);   }
        
    }
    
    
    private static String[] keyGeneration(String keyHex)
    {
        String[] roundKeys=new String[16];
        String pc1Output=permutationChoice1(keyHex);
        
        String shiftInput=new String(), shiftOutput=new String();
        shiftInput=pc1Output;
        for(int i=0;i<16 ; i++)
        {
            shiftOutput=shift(shiftInput,i);
            shiftInput=shiftOutput;
            roundKeys[i]=pemutationChoice2(shiftOutput);
            System.out.println(roundKeys[i]);
        }
                
        return roundKeys;
    }
    
    private static String permutationChoice1(String keyHex) 
    {
        int [] P ={ 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
        String actualInputBinary;
        String outputBinary =new String();
        String outputHex;
        int indexInInput;

        //takes Hex representation of a 32-bit number in a string
        //and returns its binary representation in another string
        actualInputBinary=new BigInteger(keyHex,16).toString(2);
        
        if(actualInputBinary.length()<64) // this means leading zeros eliminated
        {
                String d=new String();
                int dif=64-actualInputBinary.length();
                for(int i=0;i<dif;i++)
                        d+='0';
                d+=actualInputBinary;
                actualInputBinary=d;
        }

        for(int i=0;i<P.length;i++)
        {
                indexInInput=P[i]-1;
                outputBinary+=actualInputBinary.charAt(indexInInput);
        }
        //takes string representation of a binary number
        //and returns string representation of its hexadecimal value
        outputHex=new BigInteger(outputBinary,2).toString(16);
        return outputHex.toUpperCase();
    }

    private static String pemutationChoice2(String shiftOutput) 
    {
        int [] P ={ 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 
                    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 
                    48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
        
        String actualInputBinary;
        String outputBinary =new String();
        String outputHex;
        int indexInInput;

        //takes Hex representation of a 32-bit number in a string
        //and returns its binary representation in another string
        actualInputBinary=new BigInteger(shiftOutput,16).toString(2);
        
        if(actualInputBinary.length()<56) // this means leading zeros eliminated
        {
                String d=new String();
                int dif=56-actualInputBinary.length();
                for(int i=0;i<dif;i++)
                        d+='0';
                d+=actualInputBinary;
                actualInputBinary=d;
        }

        for(int i=0;i<P.length;i++)
        {
                indexInInput=P[i]-1;
                outputBinary+=actualInputBinary.charAt(indexInInput);
        }
        //takes string representation of a binary number
        //and returns string representation of its hexadecimal value
        outputHex=new BigInteger(outputBinary,2).toString(16);
        return outputHex.toUpperCase();
        
    }

    private static String shift(String shiftInput, int roundNum)
    {
        String shiftOutput=new String();
        int[] shift= {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1} ;
        int indexInShift=0;
        String actualInputBinary;
        String outputBinary =new String();
        
        //takes Hex representation of a 32-bit number in a string
        //and returns its binary representation in another string
        actualInputBinary=new BigInteger(shiftInput,16).toString(2);
        
        if(actualInputBinary.length()<56) // this means leading zeros eliminated
        {
                String d=new String();
                int dif=56-actualInputBinary.length();
                for(int i=0;i<dif;i++)
                        d+='0';
                d+=actualInputBinary;
                actualInputBinary=d;
        }

        int shiftValue=shift[roundNum];
        for(int j=0;j<shift.length;j++)
        {
            if(j<28)
            {
                indexInShift=(j+shiftValue)%28;
                outputBinary+=actualInputBinary.charAt(indexInShift);
            }
                
            else
            {
                indexInShift=(j+shiftValue)%28+28;
                outputBinary+=actualInputBinary.charAt(indexInShift);
            }
                
        }
        //takes string representation of a binary number
        //and returns string representation of its hexadecimal value
        shiftOutput=new BigInteger(outputBinary,2).toString(16);
        
        return shiftOutput.toUpperCase();
    }
    
}
