import common.CommonUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintStream;

/**
 * Created by tt on 2016/7/30.
 */
public class PcapAnalysis {

    //private static final String PCAP_FILE_PATH = "src/main/resources/ping.pcap";

    //private static final String OUTPUT_FILE_PATH = "src/main/resources/ddos.txt";

    //private static final String PCAP_FILE_PATH = "src/main/resources/ddos_test_10.pcap_10.pcap";
    private static final String PCAP_FILE_PATH = "src/main/resources/ping_test_10.pcap_10.pcap";

    //private static final String PCAP_FILE_PATH = "src/main/resources/cap.pcap";

    private static final String OUTPUT_FILE_PATH = "src/main/resources/1qq.txt";
    public static void main(String[] args) {
        byte[] buffer_2 = new byte[2];
        File f = new File(PCAP_FILE_PATH);
        File outPutFile = new File(OUTPUT_FILE_PATH);
        PrintStream printStream = null;
        if(outPutFile.exists()){
            outPutFile.delete();
            System.out.println("File Delete success.");
        }
        Pcap pcap = null;
        try {
            InputStream is = new FileInputStream(f);
            pcap = PcapParser.unpack(is);
            is.close();
            outPutFile.createNewFile();
            printStream = new PrintStream(outPutFile);
        } catch (Exception e) {
            e.printStackTrace();
        }

        int pcapRecordCount = pcap.getData().size();


        for (int record = 0; record < pcapRecordCount; record++) {
            byte[] t = pcap.getData().get(record).getContent();
            //System.out.println(t[23]);
            /*
            buffer_2[0] = t[34];
            buffer_2[1] = t[35];
            int sourcePort = CommonUtil.byteArrayToShort(buffer_2, 0);
            buffer_2[0] = t[36];
            buffer_2[1] = t[37];
            int destinationPort = CommonUtil.byteArrayToShort(buffer_2, 0);
            */
            StringBuilder sourceIp = new StringBuilder();
            StringBuilder destinationIp = new StringBuilder();
            for (int i = 0; i <= 3; i++) {
                int ip_source_tmp = t[26 + i] & 0x000000FF;
                int ip_destination_tmp = t[30 + i] & 0x000000FF;
                sourceIp.append(ip_source_tmp);
                destinationIp.append(ip_destination_tmp);
                if (i != 3) {
                    sourceIp.append(".");
                    destinationIp.append(".");
                }
            }

            printStream.println(sourceIp + "~" + destinationIp );

            //System.out.println((record + 1) + "\t|SourceIp\t|" + sourceIp + ":" + sourcePort + "\t|DestinationIp\t|" + destinationIp + ":" + destinationPort + "\t|");
            System.out.println(sourceIp + "~" + destinationIp);
            /*System.out.println(t.length);
            for(int i=0;i<t.length;i++){
                System.out.print(t[i]+" ");
            }
            System.out.println();*/

        }

       printStream.close();

    }
}
