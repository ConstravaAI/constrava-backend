import fs from "fs";

const target = "server.js";
let text = fs.readFileSync(target, "utf8");

const replacement = `const messages = {
        overview: "Overall performance looks healthy: the site is generating " + format(s.visits || 0) + " visits, " + format(s.leads || 0) + " leads, and " + format(s.purchases || 0) + " purchases. The strongest story is whether traffic is turning into qualified demand, not just whether views are increasing.",
        tip: "The current account is showing a real funnel pattern: visitors arrive, click into service or pricing pages, become leads, and some convert into purchases. The next move is to focus on the highest-intent pages and sources.",
        traffic: "Traffic is currently led by " + topSource + ", with " + topPage + " producing the most activity. That suggests the main growth opportunity is to keep pushing visitors toward the pages already proving they can hold attention.",
        funnel: "The funnel is converting " + leadRate + "% of visits into leads and " + purchaseRate + "% into purchases. If this were a client account, the biggest priority would be improving the step between CTA clicks and lead submissions.",
        realtime: "Recent activity shows active demand rather than dead traffic. New page views and CTA clicks indicate visitors are still exploring the offer, while lead and purchase events show the funnel is producing business outcomes.",
        pages: "The top-performing page is " + topPage + ". That page should be treated as the main conversion surface: sharpen the offer, keep the CTA visible, and use it as the model for lower-performing pages.",
        whyUp: "Traffic appears to be rising because acquisition is concentrated through " + topSource + " and the strongest pages are receiving repeated activity. The pattern looks like a campaign or offer is starting to gain traction.",
        leadQuality: "The strongest lead source is " + topSource + ". Leads from that source should be reviewed first because they are most likely connected to the traffic that is already converting.",
        nextAction: "The best next action is to improve the highest-traffic page, then compare whether the lead rate moves above " + leadRate + "%. A small lift there would create more total leads without needing more traffic.",
        crm: "The CRM pipeline shows how analytics turns into follow-up. Prioritize qualified and proposal-stage leads first, then use their source and page history to personalize outreach.",
        followup: "Follow up first with leads that came from " + topSource + " or interacted with " + topPage + ". They are showing the clearest buying signals and should get the most direct outreach.",
        qualify: "A high-quality lead here would be one connected to the strongest source, a high-intent page, and a clear request. Those leads are more valuable than generic traffic because they match the conversion path already working.",
        pipeline: "The pipeline should be judged by movement from New to Qualified to Proposal. If more leads are entering than advancing, the issue is likely follow-up speed or offer clarity rather than traffic volume.",
        menu: "This card is worth monitoring because changes in traffic, conversion, or revenue here would affect the overall account story."
      };

      return messages[topic]`;

const pattern = /const messages = \{[\s\S]*?\n      \};\n\n      return messages\[topic\]/;

if (pattern.test(text) && !text.includes("Overall performance looks healthy: the site is generating")) {
  text = text.replace(pattern, replacement);
  fs.writeFileSync(target, text);
  console.log("Updated AI explain copy to analyze the data as real performance.");
} else {
  console.log("AI explain copy already updated or target block not found.");
}
