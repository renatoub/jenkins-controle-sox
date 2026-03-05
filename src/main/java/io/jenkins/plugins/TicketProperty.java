package io.jenkins.plugins;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.export.Exported;
import org.kohsuke.stapler.export.ExportedBean;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@ExportedBean
public class TicketProperty extends JobProperty<Job<?, ?>> {

    private final List<ChangeEntry> history;

    @DataBoundConstructor
    public TicketProperty(List<ChangeEntry> history) {
        this.history = (history != null) ? history : new ArrayList<ChangeEntry>();
    }

    @Exported
    public List<ChangeEntry> getHistory() {
        return history;
    }

    @ExportedBean
    public static class ChangeEntry {
        private final String ticketNumber;
        private final String observation;
        private final String date;

        @DataBoundConstructor
        public ChangeEntry(String ticketNumber, String observation) {
            this.ticketNumber = ticketNumber;
            this.observation = observation;
            this.date = new Date().toString();
        }

        @Exported
        public String getTicketNumber() {
            return ticketNumber;
        }

        @Exported
        public String getObservation() {
            return observation;
        }

        @Exported
        public String getDate() {
            return date;
        }
    }

    @Extension
    public static final class DescriptorImpl extends JobPropertyDescriptor {

        private String apiUrl;
        private String authType;
        private String tokenHeader;
        private Secret tokenValue;
        private String apiUser;
        private Secret apiPassword;
        private String onServiceFail;
        private String onTicketNotFound;

        public DescriptorImpl() {
            load();
        }

        @Override
        public String getGlobalConfigPage() {
            return "global.jelly";
        }

        @Override
        public String getDisplayName() {
            return "Controle SOX v4.0 (Single Source)";
        }

        @Override
        public boolean isApplicable(Class<? extends Job> jobType) {
            return true;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            req.bindJSON(this, formData);
            save();
            return true;
        }

        // Getters e Setters para Data Binding
        public String getApiUrl() {
            return apiUrl;
        }

        public void setApiUrl(String apiUrl) {
            this.apiUrl = apiUrl;
        }

        public String getAuthType() {
            return authType;
        }

        public void setAuthType(String authType) {
            this.authType = authType;
        }

        public String getTokenHeader() {
            return tokenHeader;
        }

        public void setTokenHeader(String tokenHeader) {
            this.tokenHeader = tokenHeader;
        }

        public Secret getTokenValue() {
            return tokenValue;
        }

        public void setTokenValue(Secret tokenValue) {
            this.tokenValue = tokenValue;
        }

        public String getApiUser() {
            return apiUser;
        }

        public void setApiUser(String apiUser) {
            this.apiUser = apiUser;
        }

        public Secret getApiPassword() {
            return apiPassword;
        }

        public void setApiPassword(Secret apiPassword) {
            this.apiPassword = apiPassword;
        }

        public String getOnServiceFail() {
            return onServiceFail;
        }

        public void setOnServiceFail(String onServiceFail) {
            this.onServiceFail = onServiceFail;
        }

        public String getOnTicketNotFound() {
            return onTicketNotFound;
        }

        public void setOnTicketNotFound(String onTicketNotFound) {
            this.onTicketNotFound = onTicketNotFound;
        }

        public ListBoxModel doFillAuthTypeItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("Nenhuma", "NONE");
            items.add("Token no Header", "TOKEN");
            items.add("Usuário e Senha (Basic)", "BASIC");
            return items;
        }

        public ListBoxModel doFillOnServiceFailItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("Bloquear Alteração", "BLOCK");
            items.add("Permitir (Bypass com log)", "BYPASS");
            return items;
        }

        public ListBoxModel doFillOnTicketNotFoundItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("Bloquear Alteração", "BLOCK");
            items.add("Permitir (Bypass com log)", "BYPASS");
            return items;
        }

        @Override
        public JobProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            Job<?, ?> job = req.findAncestorObject(Job.class);
            List<ChangeEntry> newHistory = new ArrayList<>();

            if (job != null) {
                TicketProperty oldProp = job.getProperty(TicketProperty.class);
                if (oldProp != null)
                    newHistory.addAll(oldProp.getHistory());
            }

            String ticket = formData.optString("ticketNumber", "").trim();
            String obs = formData.optString("observation", "").trim();

            if (ticket.isEmpty() || obs.isEmpty()) {
                throw new FormException("Ticket e Observação são obrigatórios!", "ticketNumber");
            }

            String apiDescription = validateTicketRest(ticket);
            String finalObs = obs + (apiDescription.isEmpty() ? "" : " | " + apiDescription);
            newHistory.add(new ChangeEntry(ticket, finalObs));

            return new TicketProperty(newHistory);
        }

        private String validateTicketRest(String ticketNum) throws FormException {
            if (apiUrl == null || apiUrl.isEmpty())
                return "";

            HttpURLConnection conn = null;
            try {
                URL url = new URL(apiUrl);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                // Envia apenas o ticket conforme solicitado
                conn.setRequestProperty("ticket", ticketNum);

                if ("TOKEN".equals(authType) && tokenValue != null) {
                    conn.setRequestProperty(tokenHeader, tokenValue.getPlainText());
                } else if ("BASIC".equals(authType)) {
                    String auth = apiUser + ":" + Secret.toString(apiPassword);
                    conn.setRequestProperty("Authorization",
                            "Basic " + Base64.getEncoder().encodeToString(auth.getBytes("UTF-8")));
                }

                int code = conn.getResponseCode();
                if (code == 200) {
                    BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
                    StringBuilder resp = new StringBuilder();
                    String line;
                    while ((line = in.readLine()) != null)
                        resp.append(line);
                    in.close();

                    JSONObject json = JSONObject.fromObject(resp.toString());
                    JSONObject data = json.getJSONObject("data");

                    if (data.optBoolean("exists", false)) {
                        return data.optString("description", "");
                    } else {
                        if ("BLOCK".equals(onTicketNotFound)) {
                            throw new FormException("Ticket " + ticketNum + " não encontrado na base externa.",
                                    "ticketNumber");
                        }
                        return "[Ticket não encontrado]";
                    }
                }
                throw new Exception("HTTP " + code);
            } catch (FormException fe) {
                throw fe;
            } catch (Exception e) {
                if ("BLOCK".equals(onServiceFail)) {
                    throw new FormException("Erro de Validação SOX: " + e.getMessage(), "ticketNumber");
                }
                return "[Erro API: " + e.getMessage() + "]";
            } finally {
                if (conn != null)
                    conn.disconnect();
            }
        }
    }
}