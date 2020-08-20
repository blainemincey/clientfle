package com.mongodb.utils;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 *
 */
public class RandomDataGenerator {

    // Claim Types
    private static List<String> claimTypes
            = Arrays.asList(
                    "Disability",
                    "Illness",
                    "Life",
                    "Hospital",
                    "Vision",
                    "Accident",
                    "Dental"
    );

    private static ThreadLocalRandom randomGenerator = ThreadLocalRandom.current();

    /**
     *
     * @return
     */
    public static BigDecimal getRandomBigDecimal() {
        BigDecimal bd = new BigDecimal(Double.toString(randomGenerator.nextDouble(1000)));
        bd = bd.setScale(2, RoundingMode.HALF_UP);

        return bd;
    }

    /**
     *
     * @return
     */
    public static String getRandomClaimType() {
        int randomType = randomGenerator.nextInt(RandomDataGenerator.claimTypes.size());

        return RandomDataGenerator.claimTypes.get(randomType);
    }

    /**
     *
     * @return
     */
    public static java.util.Date getRandomDateSubmittedMaxYears() {
        int randomMonth = (int)(Math.random() * 12); // 12 months
        int randomYear = (int)(Math.random() * 5); // 5 years is default
        int randomDay = (int)(Math.random() * 30); // 30 days

        LocalDateTime localDateTime = LocalDateTime.now();
        LocalDateTime dateTimeSubmitted =
                localDateTime.minusMonths(randomMonth).minusDays(randomDay).minusYears(randomYear);

        return java.util.Date.from(dateTimeSubmitted.atZone( ZoneId.systemDefault()).toInstant());
    }

    /**
     * Smoke test the methods
     * @param args
     */
    public static void main(String[] args) {
        System.out.println("Testing getRandomBigDecimal.");
        for(int idx = 1; idx < 10; idx++) {
            System.out.println(RandomDataGenerator.getRandomBigDecimal());
        }

        System.out.println("Testing getRandomClaimType.");
        for(int idx = 1; idx < 10; idx++) {
            System.out.println(RandomDataGenerator.getRandomClaimType());
        }

        System.out.println("Testing getRandomDateSubmitted.");
        for(int idx = 1; idx < 10; idx++) {
            System.out.println(RandomDataGenerator.getRandomDateSubmittedMaxYears());
        }
    }

}
