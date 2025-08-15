import java.io.*;
import java.nio.file.*;
import java.util.*;

public class LogParser {
    public static void main(String[] args) throws IOException {
        String input = "logs/alerts.log";
        String output = "logs/alerts.csv";
        if (args.length >= 1) input = args[0];
        if (args.length >= 2) output = args[1];

        List<String> lines = Files.readAllLines(Paths.get(input));
        BufferedWriter bw = new BufferedWriter(new FileWriter(output));
        bw.write("timestamp,message\n");
        for (String line : lines) {
            // Expecting "YYYY-MM-DD HH:MM:SS - message"
            int sep = line.indexOf(" - ");
            if(sep>0){
                String ts = line.substring(0, sep).trim();
                String msg = line.substring(sep+3).replaceAll(",", " ");
                bw.write(String.format("\"%s\",\"%s\"\n", ts, msg));
            }
        }
        bw.close();
        System.out.println("Parsed to " + output);
    }
}
