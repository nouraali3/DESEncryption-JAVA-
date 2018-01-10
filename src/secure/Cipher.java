
package secure;

import java.math.BigInteger;


public class Cipher {
    public static String DES (String blockHex,String keyHex)
    {
        private static String DESFunction(String blockHex, String keyHex)
        {
            String expansionOutput=expansionPermutation(blockHex);        
            BigInteger bi1=new BigInteger(expansionOutput,16);
            BigInteger bi2=new BigInteger(keyHex,16);
            String xorOutputHex = bi1.xor(bi2).toString(16);

            String sBoxOutput=sBox(xorOutputHex);

            String output=straightPermutation(sBoxOutput);
            return output;
        }

        private static String expansionPermutation(String inputHex){
            int [] E ={32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
                       12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
                       24,25,26,27,28,29,28,29,30,31,32,1};
            String inputBinary;
            String outputBinary =new String();
            String outputHex;
            int indexInInput;

            //takes Hex representation of a 32-bit (big integer) number in string
            //and returns its binary representation in another string
            inputBinary= new BigInteger(inputHex,16).toString(2);


            if(inputBinary.length()<32) // this means leading zeros eliminated
            {
                    String d=new String();
                    int dif=32-inputBinary.length();
                    for(int i=0;i<dif;i++)
                            d+='0';
                    d+=inputBinary;
                    inputBinary=d;
            }

            for(int i=0;i<E.length;i++)
            {
                    indexInInput=E[i]-1;
                    outputBinary+=inputBinary.charAt(indexInInput);
            }
            //takes binary representation of a 48-bit (big integer) number in a string
            //returns its hex representation in another string
            outputHex=new BigInteger(outputBinary, 2).toString(16);    ///tricky

            return outputHex.toUpperCase();
        }

        //sbox takes Hex representation of a 48-bit number in a string
        //passes this string by 8 s-boxes
        //and returns hex representation of 32-bit number in a string 
        private static  String sBox(String inputHex) {

                String outputHex= new String();
                //sbox tables
                int [][] s1= {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                                          {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                                          {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                                          {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};
                int [][] s2= {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                                          {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                                          {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                                          {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};
                int [][] s3= {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                                          {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                                          {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                                          {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};
                int [][] s4= {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                                          {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                                          {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                                          {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};
                int [][] s5= {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                                          {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                                          {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                                          {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};
                int [][] s6= {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                                          {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                                          {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                                          {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};
                int [][] s7= {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                                          {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                                          {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                                          {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};
                int [][] s8= {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                                      {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                                      {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                                      {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

                String inputBinary=new BigInteger(inputHex,16).toString(2);  //TRICKy

                int inputSize=inputHex.length()*4; //input size in binary
                if(inputBinary.length()<inputSize) // this means leading zeros eliminated
                {
                        String d=new String();
                        int dif=inputSize-inputBinary.length();
                        for(int i=0;i<dif;i++)
                                d+='0';
                        d+=inputBinary;
                        inputBinary=d;
                }

                int section=1;
                int row;
                int column;

                for(int i=0; i<48; i+=6)
                {
                        String rowS=new String();
                        String columnS=new String();
                        rowS += inputBinary.charAt(i);
                        rowS +=inputBinary.charAt(i+5);
                        row =Integer.parseInt(rowS,2);
                        columnS =inputBinary.substring(i+1, i+5);
                        column =Integer.parseInt(columnS,2);
                        int outputDecimal=0;;
                        switch(section)
                        {
                        case 1:
                                outputDecimal=s1[row][column];
                                section++;
                                break;
                        case 2:
                                outputDecimal=s2[row][column];
                                section++;
                                break;
                        case 3:
                                outputDecimal=s3[row][column];
                                section++;
                                break;
                        case 4:
                                outputDecimal=s4[row][column];
                                section++;
                                break;
                        case 5:
                                outputDecimal=s5[row][column];
                                section++;
                                break;
                        case 6:
                                outputDecimal=s6[row][column];
                                section++;
                                break;
                        case 7:
                                outputDecimal=s7[row][column];
                                section++;
                                break;
                        case 8:
                                outputDecimal=s8[row][column];
                                section++;
                                break;
                        }
                        outputHex+=Integer.toHexString(outputDecimal);
                }
                return outputHex.toUpperCase();
        }

        private static String straightPermutation(String inputHex){
        int [] P ={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
                   2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        String actualInputBinary;
        String outputBinary =new String();
        String outputHex;
        int indexInInput;

        //takes Hex representation of a 32-bit number in a string
        //and returns its binary representation in another string
        actualInputBinary=new BigInteger(inputHex,16).toString(2);
        
        if(actualInputBinary.length()<32) // this means leading zeros eliminated
        {
                String d=new String();
                int dif=32-actualInputBinary.length();
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


    }


