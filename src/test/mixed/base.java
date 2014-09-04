public class base {
    public static void main(String[] args) {
        base b = new base();
    }

    base() {
        // call groovy to get input
        Collector collect = new Collector();
        String value = collect.getInput();

        // send to scala
        Producer produce = new Producer();
        produce.setOutput(value);
    }
}